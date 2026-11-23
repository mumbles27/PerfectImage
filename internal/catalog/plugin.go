package catalog

import (
	"context"

	"github.com/mumbles27/PerfectImage/internal/app"
)

func init() {
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "catalog" }

// Init loads the shared catalog store (embedded catalog + catalog.dirs),
// starts hot reload and serves /catalog.
func (plugin) Init(ctx context.Context, d *app.Deps) error {
	store := Shared(d.Config.Catalog.Dirs, d.Logger.With("component", "catalog"))
	if _, err := store.Reload(ctx, true); err != nil {
		return err
	}
	if iv := d.Config.Packer.CatalogReloadInterval; iv > 0 {
		d.Go(func(ctx context.Context) { store.Watch(ctx, iv) })
	}
	d.Web.AddModule(NewModule(store, d.Web, d.Audit))
	return nil
}
