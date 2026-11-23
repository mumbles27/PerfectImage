package proxmox

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// ErrClusterNotFound is returned when no cluster has the given name or ID.
var ErrClusterNotFound = errors.New("proxmox: cluster not found")

// ErrNoCredentials means the cluster has no API token configured yet.
var ErrNoCredentials = errors.New("proxmox: cluster has no API token configured")

// Cluster is a stored cluster connection. The token secret is never loaded
// into this struct; use Registry.Credentials.
type Cluster struct {
	ID                 int64
	Name               string
	Endpoint           string
	TokenID            string
	HasSecret          bool
	CAPEM              string
	CAFile             string
	Fingerprint        string
	InsecureSkipVerify bool
	DefaultNode        string
	DefaultStorage     string
	DefaultBridge      string
	DefaultPool        string
	Source             string // "ui" or "config"
	CreatedAt          time.Time
	UpdatedAt          time.Time

	sealedSecret string
}

// TLSMode describes the TLS verification mode for display.
func (c *Cluster) TLSMode() string {
	switch {
	case c.Fingerprint != "" && (c.CAPEM != "" || c.CAFile != ""):
		return "fingerprint + CA"
	case c.Fingerprint != "":
		return "fingerprint pinned"
	case c.CAPEM != "" || c.CAFile != "":
		return "CA pinned"
	case c.InsecureSkipVerify:
		return "INSECURE (no verification)"
	default:
		return "system roots"
	}
}

// ClusterInput creates or updates a cluster.
type ClusterInput struct {
	Name     string
	Endpoint string
	TokenID  string
	// Secret is the token secret. On update, empty keeps the stored secret.
	Secret             string
	CAPEM              string
	CAFile             string
	Fingerprint        string
	InsecureSkipVerify bool
	DefaultNode        string
	DefaultStorage     string
	DefaultBridge      string
	DefaultPool        string
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Normalize trims and validates the input in place.
func (in *ClusterInput) Normalize() error {
	in.Name = strings.TrimSpace(in.Name)
	in.TokenID = strings.TrimSpace(in.TokenID)
	in.Secret = strings.TrimSpace(in.Secret)
	in.CAFile = strings.TrimSpace(in.CAFile)
	in.CAPEM = strings.TrimSpace(in.CAPEM)
	for _, p := range []*string{&in.DefaultNode, &in.DefaultStorage, &in.DefaultBridge, &in.DefaultPool} {
		*p = strings.TrimSpace(*p)
	}
	var errs []error
	if !nameRe.MatchString(in.Name) {
		errs = append(errs, errors.New("name must be 1-63 characters: letters, digits, '.', '_' or '-'"))
	}
	ep, err := NormalizeEndpoint(in.Endpoint)
	if err != nil {
		errs = append(errs, err)
	}
	in.Endpoint = ep
	if in.TokenID != "" && (!strings.Contains(in.TokenID, "@") || !strings.Contains(in.TokenID, "!") ||
		strings.ContainsAny(in.TokenID, " \t\r\n=")) {
		errs = append(errs, errors.New("token id must look like USER@REALM!TOKENID"))
	}
	if strings.ContainsAny(in.Secret, " \t\r\n") {
		errs = append(errs, errors.New("token secret must not contain whitespace"))
	}
	if in.Fingerprint = strings.TrimSpace(in.Fingerprint); in.Fingerprint != "" {
		fp, err := NormalizeFingerprint(in.Fingerprint)
		if err != nil {
			errs = append(errs, err)
		}
		in.Fingerprint = fp
	}
	if in.CAPEM != "" {
		if err := checkPEM(in.CAPEM); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func checkPEM(s string) error {
	rest := []byte(s)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return errors.New("CA bundle must only contain CERTIFICATE blocks")
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return fmt.Errorf("CA bundle: %w", err)
		}
		n++
	}
	if n == 0 {
		return errors.New("CA bundle contains no PEM certificates")
	}
	return nil
}

// Store persists cluster connections in proxmox_clusters.
type Store struct {
	db     *store.DB
	sealer secrets.Sealer
	now    func() time.Time
}

// NewStore returns a cluster store.
func NewStore(db *store.DB, sealer secrets.Sealer) *Store {
	return &Store{db: db, sealer: sealer, now: time.Now}
}

func secretAAD(name string) string { return "proxmox:cluster:" + name + ":token" }

const clusterCols = `id, name, endpoint, token_id, token_secret, ca_pem, ca_file, fingerprint,
	insecure_skip_verify, default_node, default_storage, default_bridge, default_pool, source,
	created_at, updated_at`

func scanCluster(s interface{ Scan(...any) error }) (*Cluster, error) {
	var c Cluster
	var insecure int
	var created, updated int64
	if err := s.Scan(&c.ID, &c.Name, &c.Endpoint, &c.TokenID, &c.sealedSecret, &c.CAPEM, &c.CAFile,
		&c.Fingerprint, &insecure, &c.DefaultNode, &c.DefaultStorage, &c.DefaultBridge, &c.DefaultPool,
		&c.Source, &created, &updated); err != nil {
		return nil, err
	}
	c.InsecureSkipVerify = insecure != 0
	c.HasSecret = c.sealedSecret != ""
	c.CreatedAt = time.UnixMilli(created).UTC()
	c.UpdatedAt = time.UnixMilli(updated).UTC()
	return &c, nil
}

// List returns all clusters ordered by name.
func (s *Store) List(ctx context.Context) ([]*Cluster, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clusterCols+` FROM proxmox_clusters ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cluster
	for rows.Next() {
		c, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get returns the cluster with id.
func (s *Store) Get(ctx context.Context, id int64) (*Cluster, error) {
	return s.one(ctx, `WHERE id = ?`, id)
}

// GetByName returns the cluster named name.
func (s *Store) GetByName(ctx context.Context, name string) (*Cluster, error) {
	return s.one(ctx, `WHERE name = ?`, name)
}

func (s *Store) one(ctx context.Context, where string, arg any) (*Cluster, error) {
	c, err := scanCluster(s.db.QueryRowContext(ctx, `SELECT `+clusterCols+` FROM proxmox_clusters `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClusterNotFound
	}
	return c, err
}

// Create inserts a new cluster, sealing the secret.
func (s *Store) Create(ctx context.Context, in ClusterInput) (*Cluster, error) {
	return s.create(ctx, in, "ui")
}

func (s *Store) create(ctx context.Context, in ClusterInput, source string) (*Cluster, error) {
	if err := in.Normalize(); err != nil {
		return nil, err
	}
	sealed := ""
	if in.Secret != "" {
		var err error
		if sealed, err = secrets.EncryptString(s.sealer, in.Secret, secretAAD(in.Name)); err != nil {
			return nil, fmt.Errorf("proxmox: seal token: %w", err)
		}
	}
	now := s.now().UTC().UnixMilli()
	res, err := s.db.ExecContext(ctx, `INSERT INTO proxmox_clusters
		(name, endpoint, token_id, token_secret, ca_pem, ca_file, fingerprint, insecure_skip_verify,
		 default_node, default_storage, default_bridge, default_pool, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Name, in.Endpoint, in.TokenID, sealed, in.CAPEM, in.CAFile, in.Fingerprint, b2i(in.InsecureSkipVerify),
		in.DefaultNode, in.DefaultStorage, in.DefaultBridge, in.DefaultPool, source, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("a cluster named %q already exists", in.Name)
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.Get(ctx, id)
}

// Update replaces the cluster's settings. An empty in.Secret keeps the
// stored secret (re-sealed if the name changed).
func (s *Store) Update(ctx context.Context, id int64, in ClusterInput) (*Cluster, error) {
	if err := in.Normalize(); err != nil {
		return nil, err
	}
	old, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	sealed := old.sealedSecret
	switch {
	case in.Secret != "":
		sealed, err = secrets.EncryptString(s.sealer, in.Secret, secretAAD(in.Name))
	case sealed != "" && old.Name != in.Name:
		var pt string
		if pt, err = secrets.DecryptString(s.sealer, sealed, secretAAD(old.Name)); err == nil {
			sealed, err = secrets.EncryptString(s.sealer, pt, secretAAD(in.Name))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("proxmox: seal token: %w", err)
	}
	// Strictly increasing updated_at so registries notice every change.
	now := max(s.now().UTC().UnixMilli(), old.UpdatedAt.UnixMilli()+1)
	_, err = s.db.ExecContext(ctx, `UPDATE proxmox_clusters SET
		name = ?, endpoint = ?, token_id = ?, token_secret = ?, ca_pem = ?, ca_file = ?, fingerprint = ?,
		insecure_skip_verify = ?, default_node = ?, default_storage = ?, default_bridge = ?, default_pool = ?,
		updated_at = ? WHERE id = ?`,
		in.Name, in.Endpoint, in.TokenID, sealed, in.CAPEM, in.CAFile, in.Fingerprint, b2i(in.InsecureSkipVerify),
		in.DefaultNode, in.DefaultStorage, in.DefaultBridge, in.DefaultPool, now, id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("a cluster named %q already exists", in.Name)
		}
		return nil, err
	}
	return s.Get(ctx, id)
}

// Delete removes a cluster.
func (s *Store) Delete(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM proxmox_clusters WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrClusterNotFound
	}
	return nil
}

// secret unseals the cluster's token secret.
func (s *Store) secret(c *Cluster) (string, error) {
	if c.sealedSecret == "" {
		return "", ErrNoCredentials
	}
	pt, err := secrets.DecryptString(s.sealer, c.sealedSecret, secretAAD(c.Name))
	if err != nil {
		return "", fmt.Errorf("proxmox: unseal token for %s: %w", c.Name, err)
	}
	return pt, nil
}

const seededKey = "proxmox.seeded_clusters"

// Seed inserts config clusters whose names have never been seeded before.
// Names are remembered, so clusters deleted in the UI are not re-created on
// restart and the database copy always wins after the first seed. It
// returns the names that were inserted.
func (s *Store) Seed(ctx context.Context, cfg config.ProxmoxConfig) ([]string, error) {
	var seeded []string
	if v, err := s.db.GetSetting(ctx, seededKey); err == nil {
		_ = json.Unmarshal([]byte(v), &seeded)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	var inserted []string
	var errs []error
	for _, cc := range cfg.Clusters {
		if slices.Contains(seeded, cc.Name) {
			continue
		}
		if _, err := s.GetByName(ctx, cc.Name); err == nil {
			seeded = append(seeded, cc.Name) // created in the UI first
			continue
		}
		in := ClusterInput{
			Name: cc.Name, Endpoint: cc.Endpoint, TokenID: cc.TokenID, CAFile: cc.CAFile,
			Fingerprint: cc.Fingerprint, InsecureSkipVerify: cc.InsecureSkipVerify,
			DefaultNode: cc.DefaultNode, DefaultStorage: cc.DefaultStorage,
			DefaultBridge: cc.DefaultBridge, DefaultPool: cc.DefaultPool,
		}
		if cc.TokenSecretFile != "" {
			b, err := os.ReadFile(cc.TokenSecretFile)
			if err != nil {
				errs = append(errs, fmt.Errorf("cluster %s: read token_secret_file: %w", cc.Name, err))
				continue
			}
			in.Secret = strings.TrimSpace(string(b))
		}
		if _, err := s.create(ctx, in, "config"); err != nil {
			errs = append(errs, fmt.Errorf("cluster %s: %w", cc.Name, err))
			continue
		}
		seeded = append(seeded, cc.Name)
		inserted = append(inserted, cc.Name)
	}
	b, _ := json.Marshal(seeded)
	if err := s.db.SetSetting(ctx, seededKey, string(b)); err != nil {
		errs = append(errs, err)
	}
	return inserted, errors.Join(errs...)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
