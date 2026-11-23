package config

import (
	"fmt"
	"path/filepath"
	"time"
)

// AuthConfig is owned by the auth agent (internal/auth, internal/rbac).
// OIDC/LDAP connections and their secrets live in the database (sealed), not
// here; see docs/auth.md.
type AuthConfig struct {
	// DevAllowAll installs an allow-all authenticator/authorizer. Development
	// only; rejected unless server.listen is a loopback address.
	DevAllowAll bool `yaml:"dev_allow_all"`
	// SessionTTL is the idle session lifetime.
	SessionTTL time.Duration `yaml:"session_ttl"`
	// SessionAbsoluteTTL caps a session's lifetime regardless of activity.
	SessionAbsoluteTTL time.Duration `yaml:"session_absolute_ttl"`
	// PasswordMinLength is the minimum length of local passwords.
	PasswordMinLength int `yaml:"password_min_length"`
	// LockoutThreshold is the number of consecutive failed logins before an
	// account is locked; 0 uses the default, -1 disables lockout.
	LockoutThreshold int `yaml:"lockout_threshold"`
	// LockoutDuration is the first lockout period; it doubles with every
	// further failure up to LockoutMaxDuration.
	LockoutDuration    time.Duration `yaml:"lockout_duration"`
	LockoutMaxDuration time.Duration `yaml:"lockout_max_duration"`
	// LoginRatePerIP / LoginRatePerUser limit login attempts per minute;
	// -1 disables the limit.
	LoginRatePerIP   int `yaml:"login_rate_per_ip"`
	LoginRatePerUser int `yaml:"login_rate_per_user"`
	// MFARequiredRoles forces TOTP enrollment for local and LDAP users
	// holding any of these roles.
	MFARequiredRoles []string `yaml:"mfa_required_roles"`
	// APITokenMaxTTL is the longest allowed personal access token lifetime.
	APITokenMaxTTL time.Duration `yaml:"api_token_max_ttl"`
}

// ApplyDefaults implements Defaulter.
func (a *AuthConfig) ApplyDefaults(*Config) {
	if a.SessionTTL == 0 {
		a.SessionTTL = 8 * time.Hour
	}
	if a.SessionAbsoluteTTL == 0 {
		a.SessionAbsoluteTTL = max(24*time.Hour, a.SessionTTL)
	}
	if a.PasswordMinLength == 0 {
		a.PasswordMinLength = 12
	}
	if a.LockoutThreshold == 0 {
		a.LockoutThreshold = 5
	}
	if a.LockoutDuration == 0 {
		a.LockoutDuration = time.Minute
	}
	if a.LockoutMaxDuration == 0 {
		a.LockoutMaxDuration = time.Hour
	}
	if a.LoginRatePerIP == 0 {
		a.LoginRatePerIP = 30
	}
	if a.LoginRatePerUser == 0 {
		a.LoginRatePerUser = 10
	}
	if a.APITokenMaxTTL == 0 {
		a.APITokenMaxTTL = 365 * 24 * time.Hour
	}
}

// Validate implements Validator.
func (a *AuthConfig) Validate() error {
	switch {
	case a.SessionTTL < time.Minute:
		return fmt.Errorf("auth.session_ttl must be at least 1m")
	case a.SessionAbsoluteTTL < a.SessionTTL:
		return fmt.Errorf("auth.session_absolute_ttl must be >= auth.session_ttl")
	case a.PasswordMinLength < 8 || a.PasswordMinLength > 128:
		return fmt.Errorf("auth.password_min_length must be between 8 and 128")
	case a.LockoutThreshold < -1:
		return fmt.Errorf("auth.lockout_threshold must be -1 (off) or positive")
	case a.LockoutDuration < 0 || a.LockoutMaxDuration < a.LockoutDuration:
		return fmt.Errorf("auth.lockout_max_duration must be >= auth.lockout_duration >= 0")
	case a.LoginRatePerIP < -1 || a.LoginRatePerUser < -1:
		return fmt.Errorf("auth.login_rate_per_ip/user must be -1 (off) or positive")
	case a.APITokenMaxTTL < time.Hour:
		return fmt.Errorf("auth.api_token_max_ttl must be at least 1h")
	}
	return nil
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
