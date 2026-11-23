package packer

import (
	"context"
	"errors"
	"sync"
)

// ClusterCreds supplies Proxmox API credentials for a configured cluster.
// The proxmox package implements it on top of its sealed credential store
// and installs it with SetClusterCreds. tokenID is the full API token id
// ("user@realm!token"); secret is the token secret. Values are passed to
// packer only through PROXMOX_URL / PROXMOX_USERNAME / PROXMOX_TOKEN.
type ClusterCreds interface {
	Creds(ctx context.Context, cluster string) (endpoint, tokenID, secret string, insecure bool, err error)
}

// ClusterCredsFunc adapts a function to ClusterCreds.
type ClusterCredsFunc func(ctx context.Context, cluster string) (endpoint, tokenID, secret string, insecure bool, err error)

// Creds implements ClusterCreds.
func (f ClusterCredsFunc) Creds(ctx context.Context, cluster string) (string, string, string, bool, error) {
	return f(ctx, cluster)
}

// Inventory is optionally implemented by the ClusterCreds provider so the
// build wizard can offer clusters, nodes and storages to pick from.
type Inventory interface {
	Clusters(ctx context.Context) ([]string, error)
	Nodes(ctx context.Context, cluster string) ([]string, error)
	Storages(ctx context.Context, cluster, node string) ([]string, error)
}

// ErrNoCreds is returned when no ClusterCreds provider is installed.
var ErrNoCreds = errors.New("packer: no Proxmox credential provider installed (packer.SetClusterCreds)")

var (
	credsMu  sync.RWMutex
	provider ClusterCreds
)

// SetClusterCreds installs the process-wide credential provider. It may be
// called at any time (e.g. from the proxmox plugin's Init); builds look it
// up when they start.
func SetClusterCreds(c ClusterCreds) {
	credsMu.Lock()
	defer credsMu.Unlock()
	provider = c
}

func currentCreds() ClusterCreds {
	credsMu.RLock()
	defer credsMu.RUnlock()
	return provider
}
