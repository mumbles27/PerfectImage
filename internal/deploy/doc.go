// Package deploy will implement VM deployment from built templates and
// post-deploy app installation (Linux + Windows).
//
// Owner: proxmox agent. Not implemented in the foundation.
//
// Expected seams: an app.Plugin that registers job types (e.g. "deploy.vm")
// with jobs.Manager.Register and a web.Module serving /deploy guarded by
// rbac.DeployView / rbac.DeployRun.
package deploy
