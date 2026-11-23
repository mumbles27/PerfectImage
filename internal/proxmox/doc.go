// Package proxmox is the Proxmox VE API client and cluster registry.
//
// # Client
//
// [Client] is a small stdlib net/http client for the PVE REST API
// (/api2/json). It authenticates with an API token
// ("Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET"), verifies TLS by
// default (optionally against a pinned CA bundle or a pinned SHA-256
// certificate fingerprint), retries idempotent GETs with exponential backoff,
// and maps failures to typed errors ([APIError], [ErrNotFound],
// [ErrUnauthorized], [ErrForbidden], [TaskError]).
//
// The token secret is never logged and never included in errors.
//
// # Clusters and registry
//
// Cluster connections live in the proxmox_clusters table ([Store]). The token
// secret is sealed with internal/secrets (aad "proxmox:cluster:<name>:token").
// [Registry] hands out cached clients per cluster and exposes [Credentials]
// for tools such as Packer that need the raw endpoint and token (pass them via
// environment variables, never argv; see [Credentials.PackerEnv]).
//
// Other packages build their own registry from the shared dependencies:
//
//	reg := proxmox.NewRegistry(d.DB, d.Sealer, d.Logger, d.Config.Proxmox)
//	c, err := reg.Client(ctx, "lab")
//	creds, err := reg.Credentials(ctx, "lab")
//
// Registries are cheap; each one re-checks the cluster row's updated_at on
// every lookup, so edits made in the UI are picked up everywhere.
//
// # Web
//
// The plugin serves /settings/proxmox (permission proxmox.manage) to add,
// edit, delete and test cluster connections.
package proxmox
