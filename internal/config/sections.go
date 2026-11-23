package config

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
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
	Clusters []ProxmoxCluster `yaml:"clusters"`
}

// ProxmoxCluster describes one Proxmox VE endpoint.
type ProxmoxCluster struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"` // https://pve.example:8006/api2/json
	// InsecureSkipVerify disables TLS verification (lab use only).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// CAFile pins a CA bundle for the endpoint.
	CAFile string `yaml:"ca_file"`
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
	}
	return nil
}

// PackerConfig is owned by the packer agent (internal/packer, internal/catalog).
type PackerConfig struct {
	// Binary is the packer executable; empty means look up "packer" in PATH.
	Binary string `yaml:"binary"`
	// WorkDir holds per-build working directories, the plugin cache and any
	// downloaded packer binary.
	WorkDir string `yaml:"work_dir"`
	// Version, when set, is the packer release downloaded into WorkDir/bin
	// if Binary is empty and packer is not in PATH.
	Version string `yaml:"version"`
	// VersionSHA256 pins the SHA-256 of the release zip for this platform.
	// When empty the release's SHA256SUMS file is used.
	VersionSHA256 string `yaml:"version_sha256"`
	// ReleasesURL is the HashiCorp releases mirror.
	ReleasesURL string `yaml:"releases_url"`
	// BuildTimeout bounds a whole build (init, validate, build).
	BuildTimeout time.Duration `yaml:"build_timeout"`
	// InterruptGrace is how long packer gets to clean up after an interrupt
	// (cancel or timeout) before it is killed.
	InterruptGrace time.Duration `yaml:"interrupt_grace"`
	// KeepWorkDir is the per-build workdir cleanup policy:
	// never | on_failure | always.
	KeepWorkDir string `yaml:"keep_workdir"`
	// CatalogReloadInterval is how often catalog.dirs are polled for
	// changes; a negative value disables hot reload.
	CatalogReloadInterval time.Duration `yaml:"catalog_reload_interval"`
}

// ApplyDefaults implements Defaulter.
func (p *PackerConfig) ApplyDefaults(c *Config) {
	if p.WorkDir == "" {
		p.WorkDir = filepath.Join(c.DataDir, "packer")
	}
	if p.ReleasesURL == "" {
		p.ReleasesURL = "https://releases.hashicorp.com"
	}
	if p.BuildTimeout == 0 {
		p.BuildTimeout = 4 * time.Hour
	}
	if p.InterruptGrace == 0 {
		p.InterruptGrace = 2 * time.Minute
	}
	if p.KeepWorkDir == "" {
		p.KeepWorkDir = "on_failure"
	}
	if p.CatalogReloadInterval == 0 {
		p.CatalogReloadInterval = 10 * time.Second
	}
}

// Validate implements Validator.
func (p *PackerConfig) Validate() error {
	var errs []error
	switch p.KeepWorkDir {
	case "never", "on_failure", "always":
	default:
		errs = append(errs, fmt.Errorf("packer.keep_workdir %q must be never, on_failure or always", p.KeepWorkDir))
	}
	if p.Binary != "" && !filepath.IsAbs(p.Binary) {
		errs = append(errs, fmt.Errorf("packer.binary %q must be an absolute path", p.Binary))
	}
	if p.Version != "" && !packerVersionRE.MatchString(p.Version) {
		errs = append(errs, fmt.Errorf("packer.version %q must look like 1.11.2", p.Version))
	}
	if p.VersionSHA256 != "" && !sha256HexRE.MatchString(p.VersionSHA256) {
		errs = append(errs, fmt.Errorf("packer.version_sha256 must be 64 hex characters"))
	}
	if u, err := url.Parse(p.ReleasesURL); err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, fmt.Errorf("packer.releases_url %q must be an https URL", p.ReleasesURL))
	}
	if p.BuildTimeout < 0 || p.InterruptGrace < 0 {
		errs = append(errs, fmt.Errorf("packer.build_timeout and packer.interrupt_grace must be positive"))
	}
	return errors.Join(errs...)
}

var (
	packerVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256HexRE     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

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
