package auditlog

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/store"
	"github.com/mumbles27/PerfectImage/internal/web"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/ops.css
var staticFS embed.FS

// StylesheetPath is the shared stylesheet for the ops pages (audit, SIEM,
// backup); templates link it from their "head" block.
const StylesheetPath = "/ops/static/ops.css"

func init() {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	store.RegisterMigrations("audit", sub) // tables: audit_*
	app.RegisterPlugin(plugin{})
}

// registry maps a running app (its Deps) to its Store so sibling ops
// packages (siem, backup) can subscribe or reload without globals leaking
// across test instances.
var registry sync.Map // *app.Deps -> *Store

// For returns the Store installed for d, or nil if the audit plugin is not
// initialized. Plugins that need it must be initialized after this one,
// which import order guarantees for packages importing auditlog.
func For(d *app.Deps) *Store {
	s, _ := registry.Load(d)
	st, _ := s.(*Store)
	return st
}

type plugin struct{}

func (plugin) Name() string { return "audit" }

// retentionInterval is how often expired events are pruned.
const retentionInterval = 6 * time.Hour

func (plugin) Init(ctx context.Context, d *app.Deps) error {
	st, err := New(ctx, d.DB, Options{QueueSize: d.Config.SIEM.AuditQueueSize, Logger: d.Logger})
	if err != nil {
		return err
	}
	d.Audit.Set(st)
	registry.Store(d, st)
	// Registered first among ops hooks, so it runs last: other shutdown
	// hooks can still record events.
	d.OnShutdown(func(ctx context.Context) error {
		d.Audit.Set(nil)
		registry.Delete(d)
		return st.Close(ctx)
	})
	d.Web.AddModule(&module{st: st})
	d.Web.AddReadinessCheck("audit", func(context.Context) error {
		m := st.Metrics()
		if m.QueueLen*10 >= m.QueueCap*9 {
			return errors.New("audit queue nearly full")
		}
		return nil
	})
	if ret := d.Config.SIEM.AuditRetention; ret > 0 {
		d.Go(func(ctx context.Context) { retentionLoop(ctx, st, ret) })
	}
	return nil
}

func retentionLoop(ctx context.Context, st *Store, retention time.Duration) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cutoff := st.now().Add(-retention)
		n, err := st.Prune(ctx, cutoff)
		switch {
		case err != nil:
			st.log.Error("audit retention failed", "err", err)
			_ = st.Record(ctx, audit.Event{Actor: "system", Action: "audit.retention.prune",
				Outcome: audit.OutcomeFailure, Reason: err.Error()})
		case n > 0:
			_ = st.Record(ctx, audit.Event{Actor: "system", Action: "audit.retention.prune",
				Outcome: audit.OutcomeSuccess, Details: map[string]any{
					"deleted": n, "before": cutoff.Format(time.RFC3339)}})
		}
		t.Reset(retentionInterval)
	}
}

// RequestEvent returns an event pre-filled from an HTTP request: actor
// (from the authenticated principal), source IP, user agent and request ID.
func RequestEvent(r *http.Request, action, target string, outcome audit.Outcome) audit.Event {
	e := audit.Event{
		Action: action, Target: target, Outcome: outcome,
		SourceIP: remoteIP(r), UserAgent: r.UserAgent(), RequestID: web.RequestIDFrom(r.Context()),
	}
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		e.ActorID, e.Actor = p.ID, p.Username
	}
	return e
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
