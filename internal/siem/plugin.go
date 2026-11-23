package siem

import (
	"context"
	"embed"
	"io/fs"
	"runtime/debug"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

//go:embed templates/*.html
var templatesFS embed.FS

// buildVersion returns the module version or VCS revision of the binary.
func buildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return "dev-" + s.Value[:12]
		}
	}
	return "dev"
}

func init() {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	store.RegisterMigrations("siem", sub) // tables: siem_*
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "siem" }

func (plugin) Init(_ context.Context, d *app.Deps) error {
	creds := &dbCredentials{db: d.DB, sealer: d.Sealer}
	m, err := NewManager(d.Config.SIEM, creds, Options{Logger: d.Logger, Version: buildVersion()})
	if err != nil {
		return err
	}
	st := auditlog.For(d)
	if st != nil {
		st.Subscribe(m.PublishAudit)
	} else {
		d.Logger.Warn("audit log plugin not initialized; SIEM audit stream disabled", "component", "siem")
	}
	d.Logging.AddSink(logSink{m: m})
	d.OnShutdown(func(ctx context.Context) error {
		if st != nil {
			// Forward events still buffered in the audit queue before the
			// outputs stop (the audit store itself closes later).
			_ = st.Flush(ctx)
		}
		return m.Close(ctx)
	})
	d.Web.AddModule(&module{m: m, creds: creds})
	return nil
}
