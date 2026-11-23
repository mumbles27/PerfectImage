package packer

import (
	"context"
	"embed"
	"io/fs"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func init() {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	store.RegisterMigrations("packer", sub)
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "packer" }

// Init registers the packer.build job and the /build pages. It runs after
// the catalog plugin (this package imports catalog), which loads the shared
// catalog store.
func (plugin) Init(_ context.Context, d *app.Deps) error {
	svc := NewService(Options{
		Config:  d.Config.Packer,
		Catalog: catalog.Shared(d.Config.Catalog.Dirs, d.Logger.With("component", "catalog")),
		DB:      d.DB,
		Sealer:  d.Sealer,
		Audit:   d.Audit,
		Logger:  d.Logger.With("component", "packer"),
		Jobs:    d.Jobs,
	})
	if err := d.Jobs.Register(JobType, svc); err != nil {
		return err
	}
	clusters := func() []string {
		var names []string
		for _, c := range d.Config.Proxmox.Clusters {
			names = append(names, c.Name)
		}
		return names
	}
	d.Web.AddModule(NewModule(svc, d.Web, clusters))
	return nil
}
