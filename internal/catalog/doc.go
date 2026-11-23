// Package catalog loads, validates and serves the PerfectImage catalog:
// Packer image definitions, app install definitions and app bundles.
//
// Sources are layered: the embedded catalog (the repository's catalog/
// directory, see package catalogdata) first, then each directory in
// config catalog.dirs. An item in a later layer replaces the item with the
// same id ("overrides win by id"). The web editor writes to the last
// directory.
//
// Layout of every layer:
//
//	images/<id>/image.yaml   image metadata (Image)
//	images/<id>/*.pkr.hcl    Packer template (proxmox-iso source + build)
//	apps/<id>.yaml           app definition (App)
//	bundles/<id>.yaml        bundle definition (Bundle)
//
// Validation reports problems with file and line numbers (Problem). The
// store polls file mtimes and hot-reloads on change. Resolve turns app and
// bundle ids into ordered InstallSteps (dependencies first) with generated
// bash or PowerShell scripts that try each install method in order.
//
// The package registers the "catalog" app.Plugin (/catalog pages, guarded
// by rbac.CatalogView and rbac.CatalogManage) and the `catalog validate`
// CLI command. See docs/catalog.md.
package catalog
