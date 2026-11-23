package config

import (
	"errors"
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

// SIEMConfig is owned by the ops agent (internal/siem, internal/audit). Each
// output receives audit events and/or application logs. Credentials (HEC
// tokens, API keys, passwords, HMAC secrets) are never configured here: they
// are entered on /settings/siem and sealed in the database.
type SIEMConfig struct {
	Outputs []SIEMOutput `yaml:"outputs"`
	// SpillDir holds per-output on-disk spill buffers. Default <data_dir>/siem.
	SpillDir string `yaml:"spill_dir"`
	// AuditRetention is how long audit events are kept in the database
	// (0 keeps them forever). Default 365 days (8760h).
	AuditRetention time.Duration `yaml:"audit_retention"`
	// AuditQueueSize bounds the in-memory audit write buffer. Default 4096.
	AuditQueueSize int `yaml:"audit_queue_size"`
}

// SIEM output types.
const (
	SIEMTypeSyslog    = "syslog"
	SIEMTypeCEF       = "cef"
	SIEMTypeSplunkHEC = "splunk_hec"
	SIEMTypeElastic   = "elastic"
	SIEMTypeWebhook   = "webhook"
	SIEMTypeFile      = "file"
)

// SIEMOutput is a single forwarding target.
type SIEMOutput struct {
	Name string `yaml:"name"`
	// Type is one of syslog, cef, splunk_hec, elastic, webhook, file.
	Type string `yaml:"type"`
	// Disabled keeps the output configured but inactive.
	Disabled bool `yaml:"disabled"`
	// Streams selects what is forwarded: "audit", "logs" (default both).
	Streams []string `yaml:"streams"`
	// MinLevel is the minimum application log level forwarded (default info).
	MinLevel string `yaml:"min_level"`

	// Queueing. Zero values get defaults.
	QueueSize     int           `yaml:"queue_size"`     // default 1000 records
	BatchSize     int           `yaml:"batch_size"`     // default 100 records
	FlushInterval time.Duration `yaml:"flush_interval"` // default 2s
	Timeout       time.Duration `yaml:"timeout"`        // per send, default 10s
	MaxBackoff    time.Duration `yaml:"max_backoff"`    // default 5m
	SpillMaxMB    int           `yaml:"spill_max_mb"`   // default 64; -1 disables spilling

	// Address is the syslog/CEF destination: udp://host:514, tcp://host:601
	// or tls://host:6514.
	Address string `yaml:"address"`
	// Facility is the syslog facility name (default local0).
	Facility string `yaml:"facility"`
	// AppName is the syslog APP-NAME (default perfectimage).
	AppName string `yaml:"app_name"`

	// URL is the HTTP endpoint for splunk_hec (https://splunk:8088),
	// elastic (https://es:9200) and webhook outputs.
	URL string `yaml:"url"`
	// Index is the Splunk index or Elasticsearch index/data stream.
	Index string `yaml:"index"`
	// SourceType is the Splunk sourcetype (default perfectimage:json).
	SourceType string `yaml:"sourcetype"`
	// Username selects basic auth for elastic (password set in the UI).
	// When empty, the elastic output uses an API key set in the UI.
	Username string `yaml:"username"`
	// Headers are extra, non-secret HTTP headers for webhook/HTTP outputs.
	Headers map[string]string `yaml:"headers"`

	// TLS for tls:// syslog and HTTPS outputs.
	CAFile             string `yaml:"ca_file"`
	CertFile           string `yaml:"cert_file"` // client certificate (mTLS)
	KeyFile            string `yaml:"key_file"`
	ServerName         string `yaml:"server_name"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // lab use only

	// Path is the JSON-lines file for the file output.
	Path      string `yaml:"path"`
	MaxSizeMB int    `yaml:"max_size_mb"` // file rotation size, default 100
	MaxFiles  int    `yaml:"max_files"`   // rotated files kept, default 5
}

// paths returns pointers to the output's file path fields (for resolvePaths).
func (o *SIEMOutput) paths() []*string {
	return []*string{&o.CAFile, &o.CertFile, &o.KeyFile, &o.Path}
}

// ApplyDefaults implements Defaulter.
func (s *SIEMConfig) ApplyDefaults(c *Config) {
	if s.SpillDir == "" {
		s.SpillDir = filepath.Join(c.DataDir, "siem")
	}
	if s.AuditRetention == 0 {
		s.AuditRetention = 365 * 24 * time.Hour
	}
	if s.AuditQueueSize == 0 {
		s.AuditQueueSize = 4096
	}
	for i := range s.Outputs {
		o := &s.Outputs[i]
		if len(o.Streams) == 0 {
			o.Streams = []string{"audit", "logs"}
		}
		if o.MinLevel == "" {
			o.MinLevel = "info"
		}
		if o.QueueSize == 0 {
			o.QueueSize = 1000
		}
		if o.BatchSize == 0 {
			o.BatchSize = 100
		}
		if o.FlushInterval == 0 {
			o.FlushInterval = 2 * time.Second
		}
		if o.Timeout == 0 {
			o.Timeout = 10 * time.Second
		}
		if o.MaxBackoff == 0 {
			o.MaxBackoff = 5 * time.Minute
		}
		if o.SpillMaxMB == 0 {
			o.SpillMaxMB = 64
		}
		if o.Facility == "" {
			o.Facility = "local0"
		}
		if o.AppName == "" {
			o.AppName = "perfectimage"
		}
		if o.SourceType == "" {
			o.SourceType = "perfectimage:json"
		}
		if o.Index == "" && o.Type == SIEMTypeElastic {
			o.Index = "perfectimage"
		}
		if o.MaxSizeMB == 0 {
			o.MaxSizeMB = 100
		}
		if o.MaxFiles == 0 {
			o.MaxFiles = 5
		}
	}
}

// Validate implements Validator.
func (s *SIEMConfig) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if s.AuditRetention < 0 {
		add("siem.audit_retention must be >= 0")
	}
	seen := map[string]bool{}
	for i, o := range s.Outputs {
		p := fmt.Sprintf("siem.outputs[%d]", i)
		if o.Name == "" || strings.ContainsAny(o.Name, "/\\ \t:") {
			add("%s: name is required and must not contain spaces, ':' or path separators", p)
		}
		if seen[o.Name] {
			add("%s: duplicate name %q", p, o.Name)
		}
		seen[o.Name] = true
		for _, st := range o.Streams {
			if st != "audit" && st != "logs" {
				add("%s: unknown stream %q (want audit or logs)", p, st)
			}
		}
		switch strings.ToLower(o.MinLevel) {
		case "debug", "info", "warn", "warning", "error":
		default:
			add("%s: min_level %q must be one of debug, info, warn, error", p, o.MinLevel)
		}
		if o.QueueSize < 1 || o.BatchSize < 1 || o.SpillMaxMB < -1 {
			add("%s: queue_size and batch_size must be >= 1, spill_max_mb >= -1", p)
		}
		if (o.CertFile == "") != (o.KeyFile == "") {
			add("%s: cert_file and key_file must be set together", p)
		}
		switch o.Type {
		case SIEMTypeSyslog, SIEMTypeCEF:
			if !strings.HasPrefix(o.Address, "udp://") && !strings.HasPrefix(o.Address, "tcp://") &&
				!strings.HasPrefix(o.Address, "tls://") {
				add("%s: address must be udp://, tcp:// or tls://host:port", p)
			}
		case SIEMTypeSplunkHEC, SIEMTypeElastic, SIEMTypeWebhook:
			if !strings.HasPrefix(o.URL, "https://") && !strings.HasPrefix(o.URL, "http://") {
				add("%s: url must be an http(s) URL", p)
			}
		case SIEMTypeFile:
			if o.Path == "" {
				add("%s: path is required for file outputs", p)
			}
		default:
			add("%s: unknown type %q", p, o.Type)
		}
	}
	return errors.Join(errs...)
}

// BackupConfig is owned by the ops agent (internal/backup).
type BackupConfig struct {
	// Dir is where backup archives are written. Default <data_dir>/backups.
	Dir string `yaml:"dir"`
	// Retention is how many scheduled backups to keep (in Dir and CopyTo).
	Retention int `yaml:"retention"`
	// Schedule is a 5-field cron expression or descriptor ("@daily").
	// Empty disables scheduled backups.
	Schedule string `yaml:"schedule"`
	// CopyTo is an optional second directory or UNC path
	// (\\server\share\perfectimage on Windows) that receives a copy of each backup.
	CopyTo string `yaml:"copy_to"`
	// IncludeMasterKey stores the host master key inside the (passphrase
	// encrypted) archive so sealed credentials survive a restore on a new
	// host. Default true.
	IncludeMasterKey *bool `yaml:"include_master_key"`
	// MaxUploadMB limits archive uploads on /settings/backup. Default 2048.
	MaxUploadMB int `yaml:"max_upload_mb"`
}

// MasterKeyIncluded reports whether backups include the master key (default true).
func (b BackupConfig) MasterKeyIncluded() bool {
	return b.IncludeMasterKey == nil || *b.IncludeMasterKey
}

// ApplyDefaults implements Defaulter.
func (b *BackupConfig) ApplyDefaults(c *Config) {
	if b.Dir == "" {
		b.Dir = filepath.Join(c.DataDir, "backups")
	}
	if b.Retention == 0 {
		b.Retention = 7
	}
	if b.MaxUploadMB == 0 {
		b.MaxUploadMB = 2048
	}
}

// Validate implements Validator.
func (b *BackupConfig) Validate() error {
	if b.Retention < 1 {
		return fmt.Errorf("backup.retention must be >= 1")
	}
	return nil
}
