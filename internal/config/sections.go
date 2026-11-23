package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// AuthConfig is owned by the auth agent (internal/auth, internal/rbac).
// Extend with session, password policy, OIDC/LDAP settings, etc.
type AuthConfig struct {
	// DevAllowAll installs an allow-all authenticator/authorizer. Development
	// only; rejected unless server.listen is a loopback address.
	DevAllowAll bool `yaml:"dev_allow_all"`
	// SessionTTL is the idle session lifetime.
	SessionTTL time.Duration `yaml:"session_ttl"`
}

// ApplyDefaults implements Defaulter.
func (a *AuthConfig) ApplyDefaults(*Config) {
	if a.SessionTTL == 0 {
		a.SessionTTL = 8 * time.Hour
	}
}

// ProxmoxConfig is owned by the proxmox agent (internal/proxmox, internal/deploy).
// Credentials must be stored sealed in the database, not in this file.
type ProxmoxConfig struct {
	// Clusters are seeded into the database the first time each name is seen.
	// After that, the database copy (edited in Settings > Proxmox) wins.
	Clusters []ProxmoxCluster `yaml:"clusters"`
	// RequestTimeout bounds a single API request. Default 30s.
	RequestTimeout time.Duration `yaml:"request_timeout"`
	// TaskTimeout bounds waiting for one Proxmox task (clone, start...). Default 30m.
	TaskTimeout time.Duration `yaml:"task_timeout"`
	// AgentTimeout bounds waiting for the QEMU guest agent after start. Default 15m.
	AgentTimeout time.Duration `yaml:"agent_timeout"`
}

// ProxmoxCluster describes one Proxmox VE endpoint.
type ProxmoxCluster struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"` // https://pve.example:8006/api2/json
	// TokenID is the API token id, USER@REALM!TOKENID.
	TokenID string `yaml:"token_id"`
	// TokenSecretFile optionally points at a 0600 file holding the token
	// secret. It is read once at seed time and sealed into the database.
	TokenSecretFile string `yaml:"token_secret_file"`
	// InsecureSkipVerify disables TLS verification (lab use only).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// CAFile pins a CA bundle for the endpoint.
	CAFile string `yaml:"ca_file"`
	// Fingerprint pins the SHA-256 fingerprint of the server certificate
	// (hex, colons optional).
	Fingerprint    string `yaml:"fingerprint"`
	DefaultNode    string `yaml:"default_node"`
	DefaultStorage string `yaml:"default_storage"`
	DefaultBridge  string `yaml:"default_bridge"`
	DefaultPool    string `yaml:"default_pool"`
}

// ApplyDefaults implements Defaulter.
func (p *ProxmoxConfig) ApplyDefaults(*Config) {
	if p.RequestTimeout == 0 {
		p.RequestTimeout = 30 * time.Second
	}
	if p.TaskTimeout == 0 {
		p.TaskTimeout = 30 * time.Minute
	}
	if p.AgentTimeout == 0 {
		p.AgentTimeout = 15 * time.Minute
	}
}

// Validate implements Validator.
func (p *ProxmoxConfig) Validate() error {
	seen := map[string]bool{}
	for i, c := range p.Clusters {
		if c.Name == "" || c.Endpoint == "" {
			return fmt.Errorf("proxmox.clusters[%d]: name and endpoint are required", i)
		}
		if seen[c.Name] {
			return fmt.Errorf("proxmox.clusters[%d]: duplicate name %q", i, c.Name)
		}
		seen[c.Name] = true
		if c.TokenID != "" && !strings.Contains(c.TokenID, "!") {
			return fmt.Errorf("proxmox.clusters[%d]: token_id must look like USER@REALM!TOKENID", i)
		}
	}
	if p.RequestTimeout < 0 || p.TaskTimeout < 0 || p.AgentTimeout < 0 {
		return fmt.Errorf("proxmox: timeouts must be >= 0")
	}
	return nil
}

// PackerConfig is owned by the packer agent (internal/packer, internal/catalog).
type PackerConfig struct {
	// Binary is the packer executable; empty means look up "packer" in PATH.
	Binary string `yaml:"binary"`
	// WorkDir holds per-build working directories.
	WorkDir string `yaml:"work_dir"`
}

// ApplyDefaults implements Defaulter.
func (p *PackerConfig) ApplyDefaults(c *Config) {
	if p.WorkDir == "" {
		p.WorkDir = filepath.Join(c.DataDir, "packer")
	}
}

// SIEMConfig is owned by the ops agent (internal/siem). Each output becomes a
// logging.Sink and/or audit.Recorder.
type SIEMConfig struct {
	Outputs []SIEMOutput `yaml:"outputs"`
}

// SIEMOutput is a single forwarding target. Type-specific settings go in
// Options so the ops agent can extend without schema churn.
type SIEMOutput struct {
	Name    string            `yaml:"name"`
	Type    string            `yaml:"type"` // e.g. syslog, http, splunk_hec
	Options map[string]string `yaml:"options"`
}

// BackupConfig is owned by the ops agent (internal/backup).
type BackupConfig struct {
	Dir       string `yaml:"dir"`
	Retention int    `yaml:"retention"`
	// Schedule is a cron-like expression interpreted by internal/backup.
	Schedule string `yaml:"schedule"`
}

// ApplyDefaults implements Defaulter.
func (b *BackupConfig) ApplyDefaults(c *Config) {
	if b.Dir == "" {
		b.Dir = filepath.Join(c.DataDir, "backups")
	}
	if b.Retention == 0 {
		b.Retention = 7
	}
}
