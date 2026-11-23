// Package web is the HTTP layer: router, middleware, templates, static
// assets, health endpoints and the core pages (Dashboard, Jobs).
//
// Domain packages contribute pages by implementing Module and calling
// Server.AddModule before Handler is first called. See module.go.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/jobs"
)

//go:embed static
var staticFS embed.FS

// ReadinessCheck reports whether a dependency is ready.
type ReadinessCheck func(ctx context.Context) error

// Options configures a Server.
type Options struct {
	Logger *slog.Logger
	Jobs   *jobs.Manager
	Audit  audit.Recorder
	// HSTS enables Strict-Transport-Security (set when serving HTTPS).
	HSTS    bool
	Version string
	// LoginPath is where unauthenticated browsers are redirected if a
	// module registers it (auth agent). Default "/login".
	LoginPath string
}

// Server is the web application.
type Server struct {
	opts Options
	log  *slog.Logger

	mu       sync.RWMutex
	authn    auth.Authenticator
	authz    auth.Authorizer
	csrf     CSRFProtector
	modules  []Module
	checks   map[string]ReadinessCheck
	nav      []NavItem
	renderer *renderer
	router   *Router
	handler  http.Handler
	buildErr error
	once     sync.Once
}

// NewServer returns a server with secure defaults: DenyAll authentication,
// permission-based authorization and origin-based CSRF protection.
func NewServer(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.LoginPath == "" {
		opts.LoginPath = "/login"
	}
	return &Server{
		opts:   opts,
		log:    opts.Logger.With("component", "web"),
		authn:  auth.DenyAll{},
		authz:  auth.PermissionAuthorizer{},
		csrf:   NewOriginCSRF(),
		checks: map[string]ReadinessCheck{},
	}
}

// SetAuthenticator installs the authenticator (auth agent / dev mode).
func (s *Server) SetAuthenticator(a auth.Authenticator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authn = a
}

// SetAuthorizer installs the authorizer.
func (s *Server) SetAuthorizer(a auth.Authorizer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authz = a
}

// SetCSRF replaces the CSRF protector. Must be called before Handler.
func (s *Server) SetCSRF(c CSRFProtector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csrf = c
}

// AddModule registers a module. Must be called before Handler.
func (s *Server) AddModule(m Module) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.modules = append(s.modules, m)
}

// AddReadinessCheck adds a named /readyz check.
func (s *Server) AddReadinessCheck(name string, c ReadinessCheck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks[name] = c
}

func (s *Server) authenticator() auth.Authenticator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authn
}

func (s *Server) authorizer() auth.Authorizer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authz
}

// Authorizer returns the active authorizer (for modules doing finer checks).
func (s *Server) Authorizer() auth.Authorizer { return s.authorizer() }

// Audit returns the audit recorder.
func (s *Server) Audit() audit.Recorder { return s.opts.Audit }

// Logger returns the web logger.
func (s *Server) Logger() *slog.Logger { return s.log }

func (s *Server) loginRegistered() bool {
	return s.router != nil && s.router.Registered(s.opts.LoginPath)
}

// CSRFToken returns the CSRF token for r ("" for origin-based protection).
func (s *Server) CSRFToken(r *http.Request) string {
	s.mu.RLock()
	c := s.csrf
	s.mu.RUnlock()
	return c.Token(r)
}

// Handler builds (once) and returns the full HTTP handler.
func (s *Server) Handler() (http.Handler, error) {
	s.once.Do(func() { s.handler, s.buildErr = s.build() })
	return s.handler, s.buildErr
}

func (s *Server) build() (http.Handler, error) {
	s.mu.Lock()
	modules := append([]Module{newCoreModule(s)}, s.modules...)
	csrf := s.csrf
	s.mu.Unlock()

	seen := map[string]bool{}
	for _, m := range modules {
		if seen[m.Name()] {
			return nil, errors.New("web: duplicate module name " + m.Name())
		}
		seen[m.Name()] = true
	}

	r, err := newRenderer(s, modules)
	if err != nil {
		return nil, err
	}
	s.renderer = r

	rt := newRouter(s)
	s.router = rt
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	rt.HandlePublic("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(staticSub))))
	rt.HandlePublic("GET /healthz", http.HandlerFunc(s.healthz))
	rt.HandlePublic("GET /readyz", http.HandlerFunc(s.readyz))

	var navs [][]NavItem
	for _, m := range modules {
		m.Routes(rt)
		navs = append(navs, m.Nav())
	}
	s.nav = mergeNav(coreNav, navs...)
	for _, item := range s.nav {
		if item.Path != "/" && !rt.Registered(item.Path) && !rt.Registered(item.Path+"/") {
			rt.Handle("GET "+item.Path, item.Permission, s.placeholder(item))
		}
	}

	return Chain(rt.mux,
		Recover(s.log),
		RequestID,
		AccessLog(s.log),
		SecurityHeaders(s.opts.HSTS),
		csrf.Protect,
		s.authenticate,
	), nil
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	checks := make(map[string]ReadinessCheck, len(s.checks))
	for k, v := range s.checks {
		checks[k] = v
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	results := map[string]string{}
	ready := true
	for name, c := range checks {
		if err := c(ctx); err != nil {
			ready = false
			results[name] = "fail"
			s.log.Warn("readiness check failed", "check", name, "err", err)
		} else {
			results[name] = "ok"
		}
	}
	status := http.StatusOK
	body := map[string]any{"status": "ready", "checks": results}
	if !ready {
		status = http.StatusServiceUnavailable
		body["status"] = "not ready"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
