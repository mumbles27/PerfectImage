// Package packer will drive HashiCorp Packer builds of Proxmox VM templates.
//
// Owner: packer agent. Not implemented in the foundation.
//
// Expected seams: an app.Plugin registering the "packer.build" job type and a
// web.Module serving /build guarded by rbac.ImagesView / rbac.ImagesBuild.
// Settings live in config.PackerConfig. Packer stdout/stderr should be piped
// into the job's *jobs.LogWriter (it is safe for concurrent use). Make sure
// variables holding credentials are passed via env/var-files, not argv, and
// never echoed to the job log.
package packer
