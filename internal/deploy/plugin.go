package deploy

import (
	"context"
	"embed"
	"io/fs"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
	"github.com/mumbles27/PerfectImage/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

//go:embed templates/*.html
var templatesFS embed.FS

func init() {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	store.RegisterMigrations("deploy", sub) // tables: deploy_*
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "deploy" }

func (plugin) Init(_ context.Context, d *app.Deps) error {
	reg := proxmox.NewRegistry(d.DB, d.Sealer, d.Logger, d.Config.Proxmox)
	src := RegistrySource{Reg: reg}
	hist := NewHistoryStore(d.DB)
	runner := &Runner{
		Clients:      src,
		Sealer:       d.Sealer,
		Audit:        d.Audit,
		History:      hist,
		Log:          d.Logger.With("component", "deploy"),
		TaskTimeout:  d.Config.Proxmox.TaskTimeout,
		AgentTimeout: d.Config.Proxmox.AgentTimeout,
	}
	if err := d.Jobs.Register(JobType, runner); err != nil {
		return err
	}
	d.Web.AddModule(&module{
		clients: src,
		sealer:  d.Sealer,
		jobs:    d.Jobs,
		history: hist,
		audit:   d.Audit,
		log:     d.Logger.With("component", "deploy.web"),
	})
	return nil
}
