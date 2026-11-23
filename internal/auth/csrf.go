package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// CSRFHeader and CSRFField carry the synchronizer token (the layout emits it
// in <meta name="csrf-token">; app.js copies it into the header for htmx).
const (
	CSRFHeader = "X-CSRF-Token"
	CSRFField  = "csrf_token"
)

// CSRF is a synchronizer-token CSRF protector (web.CSRFProtector). Signed-in
// browsers use the random per-session token stored server-side with the
// session; anonymous browsers (login forms) get a token bound to a random
// pre-session cookie. Cross-origin requests are additionally rejected via
// http.CrossOriginProtection. Requests authenticated with a Bearer API
// token carry no ambient credentials and are exempt from the token check.
//
// Protect also resolves the session once per request (and performs pending
// session-ID rotations); the Authenticator reuses that result.
type CSRF struct {
	s   *Service
	cop *http.CrossOriginProtection
}

// CSRF returns the protector backed by s.
func (s *Service) CSRF() *CSRF { return &CSRF{s: s, cop: http.NewCrossOriginProtection()} }

func skipSession(path string) bool {
	return strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/auth/static/") ||
		path == "/healthz" || path == "/readyz"
}

// Protect implements web.CSRFProtector.
func (c *CSRF) Protect(next http.Handler) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skipSession(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		st := c.s.resolve(w, r)
		r = r.WithContext(context.WithValue(r.Context(), stateKey{}, st))
		if !safeMethod(r.Method) && !isBearer(r) {
			got := r.Header.Get(CSRFHeader)
			if got == "" {
				got = r.PostFormValue(CSRFField)
			}
			want := c.s.csrfTokenFor(st)
			if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				http.Error(w, "Forbidden: invalid or missing CSRF token. Reload the page and try again.", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
	return c.cop.Handler(inner)
}

// Token implements web.CSRFProtector.
func (c *CSRF) Token(r *http.Request) string {
	st := stateFrom(r.Context())
	if st == nil {
		return ""
	}
	return c.s.csrfTokenFor(st)
}

func (s *Service) csrfTokenFor(st *reqState) string {
	if st.sess != nil {
		return st.sess.CSRFToken
	}
	if st.pre == "" || len(s.csrfKey) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write([]byte("pre-session:" + st.pre))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// resolve loads the session for r (rotating it if flagged), or ensures an
// anonymous pre-session cookie.
func (s *Service) resolve(w http.ResponseWriter, r *http.Request) *reqState {
	st := &reqState{}
	ctx := r.Context()
	if ck, err := r.Cookie(SessionCookie); err == nil && ck.Value != "" {
		ss, err := s.lookupSession(ctx, ck.Value)
		switch {
		case err == nil && ss.Rotate:
			if n, rerr := s.rotateSession(ctx, ss, ss.Stage); rerr == nil {
				s.setSessionCookie(w, n)
				st.sess, st.issued = n, true
			} else {
				s.log.Warn("rotate session", "err", rerr)
			}
		case err == nil:
			st.sess = ss
		default:
			s.clearSessionCookie(w)
		}
	}
	if st.sess != nil {
		return st
	}
	if ck, err := r.Cookie(preSessionCookie); err == nil && len(ck.Value) >= 32 && len(ck.Value) <= 64 {
		st.pre = ck.Value
		return st
	}
	st.pre = randToken(32)
	http.SetCookie(w, &http.Cookie{
		Name: preSessionCookie, Value: st.pre, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return st
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func isBearer(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	return len(h) > 7 && strings.EqualFold(h[:7], "bearer ")
}
