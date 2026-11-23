// Package deploy deploys VMs from Proxmox templates and installs post-deploy
// apps on Linux and Windows guests.
//
// # Job
//
// The "deploy.vm" job ([Runner]) clones a template, configures CPU, memory,
// network and cloud-init, grows the boot disk, starts the VM, waits for the
// QEMU guest agent, applies Windows customization (Administrator password,
// hostname, optional domain join) and runs app install steps through the
// guest agent (bash or PowerShell). Every step is written to the job log; no
// secret is ever logged. With "cleanup on failure" the VM is destroyed when a
// step fails. The outcome is audited as "deploy.vm".
//
// Secrets entered in the wizard (Windows Administrator and domain-join
// passwords) are sealed into the job payload with internal/secrets (aad
// "deploy.vm:<request id>:<field>") and only reach the guest over the guest
// agent channel as stdin, never as command-line arguments.
//
// # App resolver seam
//
// [AppResolver] turns app IDs into [InstallStep]s. The default is an empty
// [StaticResolver]; the catalog owner installs the real one with
// [SetAppResolver] from its plugin Init. If the resolver also implements
// [AppLister], the wizard offers its apps as checkboxes.
//
// # Web
//
//   - GET  /deploy                wizard (deploy.run; viewers are redirected to templates)
//   - POST /deploy                enqueue deploy.vm (deploy.run)
//   - GET  /deploy/templates      templates across all clusters (deploy.view)
//   - POST /deploy/templates/delete  delete a template (images.build)
//   - GET  /deploy/history        past deployments (deploy.view)
package deploy
