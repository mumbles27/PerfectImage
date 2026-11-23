// Package app bootstraps and runs the PerfectImage service:
// config -> logging -> secrets -> store/migrations -> jobs -> plugins -> web.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/logging"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
	"github.com/mumbles27/PerfectImage/internal/tlsutil"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// Options configures New.
type Options struct {
	Version string
	// Stdout receives JSON logs when log.stdout is enabled (default os.Stdout).
	Stdout io.Writer
	// Plugins overrides the globally registered plugins (tests).
	Plugins []Plugin
}

// App is a bootstrapped service instance.
type App struct {
	cfg  *config.Config
	opts Options
	deps *Deps
	log  *slog.Logger
	lg   *logging.Logging

	mu   sync.Mutex
	addr net.Addr
}

// New bootstraps all components but does not start listening.
func New(ctx context.Context, cfg *config.Config, opts Options) (_ *App, err error) {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Plugins == nil {
		opts.Plugins = Plugins()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	logFile := cfg.Log.File
	if logFile == "-" {
		logFile = ""
	}
	var stdout io.Writer
	if cfg.Log.StdoutEnabled() {
		stdout = opts.Stdout
	}
	lg, err := logging.Setup(logging.Options{
		Level: cfg.Log.Level, Stdout: stdout, File: logFile,
		MaxSizeMB: cfg.Log.MaxSizeMB, MaxBackups: cfg.Log.MaxBackups,
	})
	if err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, opts: opts, lg: lg, log: lg.Logger}
	defer func() {
		if err != nil {
			a.closeResources(context.Background())
		}
	}()
	a.log.Info("starting PerfectImage", "version", opts.Version, "config", cfg.Path(), "data_dir", cfg.DataDir)

	keyFile := cfg.Secrets.KeyFile
	if keyFile == "" {
		keyFile = filepath.Join(cfg.DataDir, "secrets", secrets.DefaultKeyFileName)
	}
	sealer, err := secrets.OpenSealer(keyFile)
	if err != nil {
		return nil, fmt.Errorf("open master key: %w", err)
	}

	db, err := store.Open(ctx, cfg.Database.Path, store.Options{BusyTimeout: cfg.Database.BusyTimeout})
	if err != nil {
		return nil, err
	}
	a.deps = &Deps{Config: cfg, Logger: a.log, Logging: lg, DB: db, Sealer: sealer, Audit: audit.NewSwappable()}
	if err := store.Migrate(ctx, db); err != nil {
		return nil, err
	}

	a.deps.Jobs = jobs.New(db, jobs.Options{
		Workers: cfg.Jobs.Workers, PollInterval: cfg.Jobs.PollInterval, Logger: a.log,
	})
	a.deps.Web = web.NewServer(web.Options{
		Logger:  a.log,
		Jobs:    a.deps.Jobs,
		Audit:   a.deps.Audit,
		HSTS:    !cfg.Server.TLS.Disable,
		Version: opts.Version,
	})
	if cfg.Auth.DevAllowAll {
		a.log.Warn("auth.dev_allow_all is enabled: every request is treated as an administrator; never use in production")
		a.deps.Web.SetAuthenticator(auth.DevAllowAll{})
		a.deps.Web.SetAuthorizer(auth.DevAllowAll{})
	}
	a.deps.Web.AddReadinessCheck("database", func(ctx context.Context) error { return db.PingContext(ctx) })

	if err := initPlugins(ctx, a.deps, opts.Plugins); err != nil {
		return nil, err
	}
	return a, nil
}

// Deps exposes the wired dependencies (tests and CLI commands).
func (a *App) Deps() *Deps { return a.deps }

// Addr returns the bound listener address once Run is listening.
func (a *App) Addr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addr
}

// Run serves until ctx is canceled, then shuts down gracefully. It always
// releases resources before returning.
func (a *App) Run(ctx context.Context) (err error) {
	cfg := a.cfg
	shutdownCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	}
	defer func() {
		sctx, cancel := shutdownCtx()
		defer cancel()
		a.closeResources(sctx)
	}()

	tlsCfg, err := a.tlsConfig()
	if err != nil {
		return err
	}
	handler, err := a.deps.Web.Handler()
	if err != nil {
		return err
	}

	if err := a.deps.Jobs.Start(ctx); err != nil {
		return err
	}
	var jobsRunning atomic.Bool
	jobsRunning.Store(true)
	a.deps.Web.AddReadinessCheck("jobs", func(context.Context) error {
		if !jobsRunning.Load() {
			return errors.New("job workers not running")
		}
		return nil
	})

	bgCtx, bgCancel := context.WithCancel(ctx)
	defer bgCancel()
	var bgWG sync.WaitGroup
	a.deps.mu.Lock()
	for _, fn := range a.deps.background {
		bgWG.Add(1)
		go func() { defer bgWG.Done(); fn(bgCtx) }()
	}
	a.deps.mu.Unlock()

	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Server.Listen, err)
	}
	a.mu.Lock()
	a.addr = ln.Addr()
	a.mu.Unlock()

	// Request contexts derive from baseCtx, canceled at shutdown so long-lived
	// requests (SSE) end promptly.
	baseCtx, baseCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer baseCancel()
	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(a.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}
	serveErr := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			serveErr <- srv.ServeTLS(ln, "", "")
		} else {
			serveErr <- srv.Serve(ln)
		}
	}()
	scheme := "https"
	if tlsCfg == nil {
		scheme = "http"
	}
	a.log.Info("listening", "addr", ln.Addr().String(), "scheme", scheme)

	select {
	case <-ctx.Done():
		a.log.Info("shutdown requested")
	case err = <-serveErr:
		a.log.Error("http server stopped unexpectedly", "err", err)
	}

	sctx, cancel := shutdownCtx()
	defer cancel()
	baseCancel()
	if sErr := srv.Shutdown(sctx); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
		a.log.Warn("http shutdown", "err", sErr)
		_ = srv.Close()
	}
	if jErr := a.deps.Jobs.Stop(sctx); jErr != nil {
		a.log.Warn("job shutdown", "err", jErr)
	}
	jobsRunning.Store(false)
	bgCancel()
	bgWG.Wait()
	a.log.Info("shutdown complete")
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func (a *App) tlsConfig() (*tls.Config, error) {
	t := a.cfg.Server.TLS
	if t.Disable {
		a.log.Warn("TLS disabled; serving plain HTTP on loopback only")
		return nil, nil
	}
	certFile, keyFile := t.CertFile, t.KeyFile
	if t.AutoTLS() {
		var generated bool
		var err error
		certFile, keyFile, generated, err = tlsutil.EnsureSelfSigned(a.cfg.TLSDir(), t.SelfSignedHosts, time.Now())
		if err != nil {
			return nil, fmt.Errorf("self-signed certificate: %w", err)
		}
		if generated {
			a.log.Warn("generated self-signed TLS certificate; configure server.tls.cert_file/key_file for production",
				"cert", certFile)
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
}

func (a *App) closeResources(ctx context.Context) {
	if a.deps != nil {
		a.deps.mu.Lock()
		hooks := a.deps.onShutdown
		a.deps.onShutdown = nil
		a.deps.mu.Unlock()
		for i := len(hooks) - 1; i >= 0; i-- {
			if err := hooks[i](ctx); err != nil {
				a.log.Warn("shutdown hook", "err", err)
			}
		}
		if a.deps.DB != nil {
			if err := a.deps.DB.Close(); err != nil {
				a.log.Warn("close database", "err", err)
			}
			a.deps.DB = nil
		}
	}
	if a.lg != nil {
		_ = a.lg.Close()
		a.lg = nil
	}
}
