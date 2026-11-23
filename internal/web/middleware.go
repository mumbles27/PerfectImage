package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares so the first one is outermost.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// CSRFProtector protects state-changing requests. The auth agent may replace
// the default (stdlib cross-origin protection based on Sec-Fetch-Site/Origin)
// with a token-based implementation via Server.SetCSRF.
type CSRFProtector interface {
	// Protect wraps next, rejecting forged unsafe requests.
	Protect(next http.Handler) http.Handler
	// Token returns the token to embed in forms/htmx headers for r ("" if the
	// implementation is not token based). Templates expose it as .CSRFToken,
	// sent as the X-CSRF-Token header by htmx and as the "csrf_token" field.
	Token(r *http.Request) string
}

// OriginCSRF is the default CSRFProtector built on http.CrossOriginProtection.
type OriginCSRF struct{ cop *http.CrossOriginProtection }

// NewOriginCSRF returns the default protector.
func NewOriginCSRF() *OriginCSRF { return &OriginCSRF{cop: http.NewCrossOriginProtection()} }

// Protect implements CSRFProtector.
func (o *OriginCSRF) Protect(next http.Handler) http.Handler { return o.cop.Handler(next) }

// Token implements CSRFProtector.
func (o *OriginCSRF) Token(*http.Request) string { return "" }

type requestIDKey struct{}

// RequestIDFrom returns the request ID stored in ctx.
func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey{}).(string)
	return s
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// RequestID assigns (or propagates a well-formed X-Request-ID) request ID.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// statusWriter records the status code and bytes written. It supports
// http.ResponseController (Flush for SSE) through Unwrap.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// AccessLog logs one structured line per request. Query strings are omitted
// to avoid logging tokens.
func AccessLog(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			// Principal is resolved further down the chain; capture via holder.
			holder := &principalHolder{}
			next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), principalHolderKey{}, holder)))
			if sw.status == 0 {
				sw.status = http.StatusOK
			}
			lvl := slog.LevelInfo
			if sw.status >= 500 {
				lvl = slog.LevelError
			} else if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || strings.HasPrefix(r.URL.Path, "/static/") {
				lvl = slog.LevelDebug
			}
			attrs := []slog.Attr{
				slog.String("request_id", RequestIDFrom(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.Int64("bytes", sw.bytes),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.String("remote", clientIP(r)),
			}
			if holder.p != nil {
				attrs = append(attrs, slog.String("user", holder.p.Username))
			}
			log.LogAttrs(r.Context(), lvl, "http request", attrs...)
		})
	}
}

type principalHolderKey struct{}
type principalHolder struct{ p *auth.Principal }

// Recover converts panics into 500 responses and logs the stack.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler {
						panic(v)
					}
					log.Error("panic serving request",
						"request_id", RequestIDFrom(r.Context()),
						"path", r.URL.Path,
						"panic", fmt.Sprint(v),
						"stack", string(debug.Stack()))
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ContentSecurityPolicy is the CSP applied to every response. Only same-origin
// scripts/styles are allowed; no inline script or style.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// SecurityHeaders sets CSP and hardening headers. HSTS is sent when hsts is true.
func SecurityHeaders(hsts bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", ContentSecurityPolicy)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// authenticate resolves the principal (if any) and stores it in the context.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		p, err := s.authenticator().Authenticate(r)
		if err != nil && !errors.Is(err, auth.ErrUnauthenticated) {
			s.log.Warn("authentication error", "request_id", RequestIDFrom(r.Context()), "err", err)
		}
		if err != nil {
			p = nil
		}
		if p != nil {
			if h, ok := r.Context().Value(principalHolderKey{}).(*principalHolder); ok {
				h.p = p
			}
			r = r.WithContext(auth.WithPrincipal(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermission returns middleware that requires a signed-in principal
// holding perm (empty perm: any signed-in principal). Unauthenticated browser
// GETs are redirected to the login page when one is registered.
func (s *Server) RequirePermission(perm rbac.Permission) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := auth.PrincipalFrom(r.Context())
			if p == nil {
				if r.Method == http.MethodGet && r.Header.Get("HX-Request") == "" && s.loginRegistered() &&
					!strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
					http.Redirect(w, r, s.opts.LoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
					return
				}
				s.Error(w, r, http.StatusUnauthorized, "Sign-in required.")
				return
			}
			if perm != "" {
				if err := s.authorizer().Authorize(r.Context(), p, perm); err != nil {
					_ = s.opts.Audit.Record(r.Context(), audit.Event{
						ActorID: p.ID, Actor: p.Username, Action: "authz.deny",
						Target: r.Method + " " + r.URL.Path, Outcome: audit.OutcomeDenied,
						Reason: "missing permission " + string(perm), SourceIP: clientIP(r),
						UserAgent: r.UserAgent(), RequestID: RequestIDFrom(r.Context()),
					})
					s.Error(w, r, http.StatusForbidden, "You do not have permission to access this page.")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
