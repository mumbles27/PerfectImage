package proxmox

import (
	"context"
	"embed"
	"io/fs"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

func init() {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	store.RegisterMigrations("proxmox", sub) // tables: proxmox_*
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "proxmox" }

func (plugin) Init(ctx context.Context, d *app.Deps) error {
	reg := NewRegistry(d.DB, d.Sealer, d.Logger, d.Config.Proxmox)
	inserted, err := reg.Store().Seed(ctx, d.Config.Proxmox)
	if err != nil {
		// A bad seed entry (e.g. unreadable token file) must not stop the
		// service; the cluster can be fixed in the UI.
		d.Logger.Warn("proxmox: seeding clusters from config", "err", err)
	}
	if len(inserted) > 0 {
		d.Logger.Info("proxmox: seeded clusters from config", "clusters", inserted)
	}
	d.Web.AddModule(newModule(reg, d.Audit, d.Logger))
	return nil
}
