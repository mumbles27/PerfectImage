// Package proxmox will contain the Proxmox VE API client (nodes, storage,
// templates, VM clone/config, task polling).
//
// Owner: proxmox agent. Not implemented in the foundation.
//
// Conventions for the owner:
//   - API tokens are sealed with internal/secrets before storage; never log them.
//   - Register tables with store.RegisterMigrations("proxmox", fs).
//   - Long operations run as jobs (see internal/jobs) and stream progress to
//     the job LogWriter.
//   - Cluster endpoints come from config.ProxmoxConfig.
package proxmox
