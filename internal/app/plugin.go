package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/logging"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// Plugin is how a domain package wires itself into the running service.
// Register one from an init function and blank-import the package from
// cmd/perfectimage/plugins.go:
//
//	func init() { app.RegisterPlugin(plugin{}) }
//
//	func (plugin) Init(ctx context.Context, d *app.Deps) error {
//		svc := newService(d.DB, d.Sealer, d.Audit, d.Logger)
//		if err := d.Jobs.Register("packer.build", svc); err != nil { return err }
//		d.Web.AddModule(svc.webModule())
//		return nil
//	}
//
// Init runs after migrations and before the job workers and HTTP listener
// start, in registration (import) order.
type Plugin interface {
	Name() string
	Init(ctx context.Context, d *Deps) error
}

var (
	pluginsMu sync.Mutex
	plugins   []Plugin
)

// RegisterPlugin registers a plugin. Panics on duplicate names.
func RegisterPlugin(p Plugin) {
	pluginsMu.Lock()
	defer pluginsMu.Unlock()
	for _, q := range plugins {
		if q.Name() == p.Name() {
			panic("app: plugin " + p.Name() + " registered twice")
		}
	}
	plugins = append(plugins, p)
}

// Plugins returns the registered plugins in registration order.
func Plugins() []Plugin {
	pluginsMu.Lock()
	defer pluginsMu.Unlock()
	return append([]Plugin(nil), plugins...)
}

// Deps are the shared services handed to plugins.
type Deps struct {
	Config  *config.Config
	Logger  *slog.Logger
	Logging *logging.Logging // AddSink for SIEM forwarders
	DB      *store.DB
	Sealer  secrets.Sealer
	Jobs    *jobs.Manager
	// Audit is shared by every component; the ops agent calls Audit.Set to
	// install the persistent recorder.
	Audit *audit.Swappable
	// Web accepts modules, authenticator/authorizer/CSRF overrides and
	// readiness checks.
	Web *web.Server

	mu         sync.Mutex
	onShutdown []func(context.Context) error
	background []func(context.Context)
}

// OnShutdown registers a hook run (in reverse order) during graceful shutdown,
// after the HTTP server and job workers have stopped.
func (d *Deps) OnShutdown(fn func(context.Context) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onShutdown = append(d.onShutdown, fn)
}

// Go registers a background task started with the service; its context is
// canceled at shutdown and the app waits for it to return.
func (d *Deps) Go(fn func(ctx context.Context)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.background = append(d.background, fn)
}

func initPlugins(ctx context.Context, d *Deps, ps []Plugin) error {
	for _, p := range ps {
		if err := p.Init(ctx, d); err != nil {
			return fmt.Errorf("plugin %s: %w", p.Name(), err)
		}
		d.Logger.Debug("plugin initialized", "plugin", p.Name())
	}
	return nil
}
