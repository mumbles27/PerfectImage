package proxmox

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// Credentials are the raw connection details of a cluster, for tools such as
// Packer. Pass them to child processes via environment variables (see
// PackerEnv), never argv, and never log them. String redacts the secret.
type Credentials struct {
	Cluster            string
	Endpoint           string // https://host:8006/api2/json
	TokenID            string // USER@REALM!TOKENID
	Secret             string
	InsecureSkipVerify bool
	// CAPEM / CAFile / Fingerprint describe TLS pinning, if configured.
	CAPEM       string
	CAFile      string
	Fingerprint string
}

// String implements fmt.Stringer without exposing the secret.
func (c Credentials) String() string {
	return "proxmox.Credentials{cluster=" + c.Cluster + " endpoint=" + c.Endpoint + " token_id=" + c.TokenID + " secret=REDACTED}"
}

// GoString implements fmt.GoStringer without exposing the secret.
func (c Credentials) GoString() string { return c.String() }

// LogValue implements slog.LogValuer without exposing the secret.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.String("cluster", c.Cluster), slog.String("endpoint", c.Endpoint),
		slog.String("token_id", c.TokenID))
}

// PackerEnv returns the environment variables read by the Packer proxmox
// plugin: PROXMOX_URL, PROXMOX_USERNAME (the token id) and PROXMOX_TOKEN.
// The plugin has no env var for TLS skipping; use InsecureSkipVerify for the
// insecure_skip_tls_verify template variable.
func (c Credentials) PackerEnv() []string {
	return []string{
		"PROXMOX_URL=" + c.Endpoint,
		"PROXMOX_USERNAME=" + c.TokenID,
		"PROXMOX_TOKEN=" + c.Secret,
	}
}

// Registry builds and caches one Client per cluster. It is safe for
// concurrent use. Cached clients are rebuilt when the cluster row changes.
type Registry struct {
	store *Store
	log   *slog.Logger
	cfg   config.ProxmoxConfig

	mu    sync.Mutex
	cache map[int64]cachedClient
}

type cachedClient struct {
	updated int64
	c       *Client
}

// NewRegistry returns a registry backed by the proxmox_clusters table.
// cfg supplies timeouts (cfg.Clusters is ignored; see Store.Seed).
func NewRegistry(db *store.DB, sealer secrets.Sealer, log *slog.Logger, cfg config.ProxmoxConfig) *Registry {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Registry{store: NewStore(db, sealer), log: log, cfg: cfg, cache: map[int64]cachedClient{}}
}

// Store returns the underlying cluster store.
func (r *Registry) Store() *Store { return r.store }

// Clusters lists configured clusters.
func (r *Registry) Clusters(ctx context.Context) ([]*Cluster, error) { return r.store.List(ctx) }

// Client returns the client for the named cluster.
func (r *Registry) Client(ctx context.Context, name string) (*Client, error) {
	c, err := r.store.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return r.ClientFor(c)
}

// ClientFor returns the client for a cluster loaded from the store.
func (r *Registry) ClientFor(c *Cluster) (*Client, error) {
	upd := c.UpdatedAt.UnixMilli()
	r.mu.Lock()
	if cc, ok := r.cache[c.ID]; ok && cc.updated == upd {
		r.mu.Unlock()
		return cc.c, nil
	}
	r.mu.Unlock()

	secret, err := r.store.secret(c)
	if err != nil {
		return nil, err
	}
	cl, err := New(r.options(c, secret))
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[c.ID] = cachedClient{updated: upd, c: cl}
	r.mu.Unlock()
	return cl, nil
}

// NewClientFromInput builds an uncached client from unsaved form input (the
// "test connection" button). If in.Secret is empty and existing is non-nil,
// the stored secret of existing is used.
func (r *Registry) NewClientFromInput(in ClusterInput, existing *Cluster) (*Client, error) {
	if err := in.Normalize(); err != nil {
		return nil, err
	}
	secret := in.Secret
	if secret == "" && existing != nil {
		var err error
		if secret, err = r.store.secret(existing); err != nil {
			return nil, err
		}
	}
	if secret == "" {
		return nil, ErrNoCredentials
	}
	c := &Cluster{Name: in.Name, Endpoint: in.Endpoint, TokenID: in.TokenID, CAPEM: in.CAPEM, CAFile: in.CAFile,
		Fingerprint: in.Fingerprint, InsecureSkipVerify: in.InsecureSkipVerify}
	return New(r.options(c, secret))
}

func (r *Registry) options(c *Cluster, secret string) Options {
	return Options{
		Endpoint:           c.Endpoint,
		TokenID:            c.TokenID,
		Secret:             secret,
		CAPEM:              []byte(c.CAPEM),
		CAFile:             c.CAFile,
		Fingerprint:        c.Fingerprint,
		InsecureSkipVerify: c.InsecureSkipVerify,
		Timeout:            r.cfg.RequestTimeout,
		Logger:             r.log.With("cluster", c.Name),
	}
}

// Credentials returns the raw credentials of the named cluster (for Packer).
func (r *Registry) Credentials(ctx context.Context, name string) (Credentials, error) {
	c, err := r.store.GetByName(ctx, name)
	if err != nil {
		return Credentials{}, err
	}
	secret, err := r.store.secret(c)
	if err != nil {
		return Credentials{}, err
	}
	if strings.TrimSpace(c.TokenID) == "" {
		return Credentials{}, ErrNoCredentials
	}
	return Credentials{
		Cluster: c.Name, Endpoint: c.Endpoint, TokenID: c.TokenID, Secret: secret,
		InsecureSkipVerify: c.InsecureSkipVerify, CAPEM: c.CAPEM, CAFile: c.CAFile, Fingerprint: c.Fingerprint,
	}, nil
}

// Forget drops a cached client (after delete).
func (r *Registry) Forget(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, id)
}
