// Package integration wires the domain packages together through their
// published seams, so no domain package has to import another:
//
//   - packer.SetClusterCreds gets a provider backed by proxmox.Registry
//     (credentials for Packer, plus cluster/node/storage inventory for the
//     build wizard).
//   - deploy.SetAppResolver gets a resolver backed by the shared catalog
//     store (post-deploy app installs).
package integration

import (
	"context"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/deploy"
	"github.com/mumbles27/PerfectImage/internal/packer"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
)

func init() {
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "integration" }

// Init installs the cross-package adapters. Both seams are process-wide
// setters that are safe to call in any plugin order: builds and deploys look
// them up when they run, and catalog.Shared returns the same store the
// catalog plugin loads.
func (plugin) Init(_ context.Context, d *app.Deps) error {
	reg := proxmox.NewRegistry(d.DB, d.Sealer, d.Logger.With("component", "proxmox"), d.Config.Proxmox)
	creds := &ProxmoxCreds{Registry: reg, Logger: d.Logger}
	packer.SetClusterCreds(creds)
	packer.SetSeedStore(creds)
	d.OnShutdown(creds.Close)

	cat := catalog.Shared(d.Config.Catalog.Dirs, d.Logger.With("component", "catalog"))
	deploy.SetAppResolver(&CatalogResolver{Catalog: cat.Catalog})
	return nil
}
