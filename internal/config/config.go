// Package config loads, defaults and validates the PerfectImage YAML
// configuration file.
//
// Extension points for domain packages:
//
//   - Each domain owns a typed section struct in sections.go (AuthConfig,
//     ProxmoxConfig, SIEMConfig, BackupConfig, PackerConfig). Owners add fields
//     to their own struct; they do not need to touch Config itself.
//   - A section struct may implement Validator (Validate() error) and/or
//     Defaulter (ApplyDefaults(c *Config)). Config.Validate and
//     Config.ApplyDefaults call them automatically for every section.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Validator is implemented by config sections that validate themselves.
type Validator interface {
	Validate() error
}

// Defaulter is implemented by config sections that fill in their own defaults.
// It receives the root config so derived paths (e.g. under DataDir) can be set.
type Defaulter interface {
	ApplyDefaults(c *Config)
}

// Config is the root configuration document.
type Config struct {
	// DataDir holds the database, TLS material, master key and logs.
	DataDir  string         `yaml:"data_dir"`
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Log      LogConfig      `yaml:"log"`
	Jobs     JobsConfig     `yaml:"jobs"`
	Catalog  CatalogConfig  `yaml:"catalog"`
	Secrets  SecretsConfig  `yaml:"secrets"`

	// Domain sections (see sections.go).
	Auth    AuthConfig    `yaml:"auth"`
	Proxmox ProxmoxConfig `yaml:"proxmox"`
	Packer  PackerConfig  `yaml:"packer"`
	SIEM    SIEMConfig    `yaml:"siem"`
	Backup  BackupConfig  `yaml:"backup"`

	// path is the file the config was loaded from (empty for defaults).
	path string
}

// ServerConfig configures the HTTP(S) listener.
type ServerConfig struct {
	Listen          string        `yaml:"listen"`
	TLS             TLSConfig     `yaml:"tls"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	// PublicURL is the externally visible base URL (used for links/cookies).
	PublicURL string `yaml:"public_url"`
}

// TLSConfig configures HTTPS. When CertFile/KeyFile are empty and Disable is
// false, a self-signed certificate is generated under DataDir/tls.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Disable serves plain HTTP. Only allowed on loopback listeners.
	Disable bool `yaml:"disable"`
	// SelfSignedHosts are extra DNS names / IPs for the generated certificate.
	SelfSignedHosts []string `yaml:"self_signed_hosts"`
}

// AutoTLS reports whether a self-signed certificate should be generated.
func (t TLSConfig) AutoTLS() bool {
	return !t.Disable && t.CertFile == "" && t.KeyFile == ""
}

// DatabaseConfig configures SQLite.
type DatabaseConfig struct {
	Path        string        `yaml:"path"`
	BusyTimeout time.Duration `yaml:"busy_timeout"`
}

// LogConfig configures structured logging.
type LogConfig struct {
	Level string `yaml:"level"` // debug, info, warn, error
	// File is the rotating JSON log file. "-" disables file logging.
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	// Stdout also writes JSON logs to stdout (journald on Linux).
	Stdout *bool `yaml:"stdout"`
}

// StdoutEnabled reports whether stdout logging is on (default true).
func (l LogConfig) StdoutEnabled() bool { return l.Stdout == nil || *l.Stdout }

// JobsConfig configures the background job queue.
type JobsConfig struct {
	Workers int `yaml:"workers"`
	// PollInterval is how often idle workers check for queued jobs.
	PollInterval time.Duration `yaml:"poll_interval"`
}

// CatalogConfig lists directories containing image/app catalog definitions.
type CatalogConfig struct {
	Dirs []string `yaml:"dirs"`
}

// SecretsConfig configures the master key used for sealing secrets at rest.
type SecretsConfig struct {
	// KeyFile overrides the master key location. Default DataDir/secrets/master.key
	// (Linux) or DataDir\secrets\master.key.dpapi (Windows, DPAPI-protected).
	KeyFile string `yaml:"key_file"`
}

// Default returns a config populated with defaults.
func Default() *Config {
	c := &Config{}
	c.ApplyDefaults()
	return c
}

// Path returns the file the config was loaded from.
func (c *Config) Path() string { return c.path }

// Load reads, defaults and validates the config at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c, err := parse(b, filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.path = abs
	return c, nil
}

// Parse decodes YAML (rejecting unknown keys), applies defaults and validates.
// Relative paths are left relative to the working directory; Load instead
// resolves them against the config file's directory.
func Parse(b []byte) (*Config, error) { return parse(b, "") }

func parse(b []byte, baseDir string) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if baseDir != "" {
		c.resolvePaths(baseDir)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// ApplyDefaults fills zero values with defaults. It is idempotent.
func (c *Config) ApplyDefaults() {
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir()
	}
	if c.Server.Listen == "" {
		c.Server.Listen = ":8443"
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = 30 * time.Second
	}
	if c.Database.Path == "" {
		c.Database.Path = filepath.Join(c.DataDir, "perfectimage.db")
	}
	if c.Database.BusyTimeout == 0 {
		c.Database.BusyTimeout = 5 * time.Second
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.File == "" {
		c.Log.File = filepath.Join(c.DataDir, "logs", "perfectimage.log")
	}
	if c.Log.MaxSizeMB == 0 {
		c.Log.MaxSizeMB = 50
	}
	if c.Log.MaxBackups == 0 {
		c.Log.MaxBackups = 5
	}
	if c.Jobs.Workers == 0 {
		c.Jobs.Workers = 2
	}
	if c.Jobs.PollInterval == 0 {
		c.Jobs.PollInterval = 2 * time.Second
	}
	if len(c.Catalog.Dirs) == 0 {
		c.Catalog.Dirs = []string{filepath.Join(c.DataDir, "catalog")}
	}
	for _, s := range c.sections() {
		if d, ok := s.(Defaulter); ok {
			d.ApplyDefaults(c)
		}
	}
}

// resolvePaths makes explicitly configured relative paths absolute against
// base, so a service whose working directory is e.g. System32 still finds
// them. Domain owners adding path fields should add them here.
func (c *Config) resolvePaths(base string) {
	abs := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	for _, p := range []*string{
		&c.DataDir, &c.Database.Path, &c.Server.TLS.CertFile, &c.Server.TLS.KeyFile,
		&c.Secrets.KeyFile, &c.Packer.WorkDir, &c.Backup.Dir, &c.Backup.CopyTo, &c.SIEM.SpillDir,
	} {
		abs(p)
	}
	if c.Log.File != "-" {
		abs(&c.Log.File)
	}
	for i := range c.Catalog.Dirs {
		abs(&c.Catalog.Dirs[i])
	}
	for i := range c.SIEM.Outputs {
		for _, p := range c.SIEM.Outputs[i].paths() {
			abs(p)
		}
	}
	for i := range c.Proxmox.Clusters {
		abs(&c.Proxmox.Clusters[i].CAFile)
		abs(&c.Proxmox.Clusters[i].TokenSecretFile)
	}
}

// TLSDir is where auto-generated TLS material lives.
func (c *Config) TLSDir() string { return filepath.Join(c.DataDir, "tls") }

// Validate checks the config for errors, collecting all problems.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !filepath.IsAbs(c.DataDir) && !strings.HasPrefix(c.DataDir, ".") {
		add("data_dir %q must be absolute or explicitly relative (./...)", c.DataDir)
	}
	host, _, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		add("server.listen %q: %v", c.Server.Listen, err)
	}
	if (c.Server.TLS.CertFile == "") != (c.Server.TLS.KeyFile == "") {
		add("server.tls.cert_file and server.tls.key_file must be set together")
	}
	if c.Server.TLS.Disable && err == nil && !IsLoopback(host) {
		add("server.tls.disable is only allowed on a loopback listen address (got %q)", c.Server.Listen)
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		add("log.level %q must be one of debug, info, warn, error", c.Log.Level)
	}
	if c.Log.MaxSizeMB < 0 || c.Log.MaxBackups < 0 {
		add("log.max_size_mb and log.max_backups must be >= 0")
	}
	if c.Jobs.Workers < 1 || c.Jobs.Workers > 64 {
		add("jobs.workers must be between 1 and 64 (got %d)", c.Jobs.Workers)
	}
	if c.Auth.DevAllowAll && err == nil && !IsLoopback(host) {
		add("auth.dev_allow_all is only allowed on a loopback listen address (got %q)", c.Server.Listen)
	}
	for _, s := range c.sections() {
		if v, ok := s.(Validator); ok {
			if err := v.Validate(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// sections returns pointers to every section so optional interfaces can be
// discovered. Domain owners: add new top-level sections here.
func (c *Config) sections() []any {
	return []any{&c.Auth, &c.Proxmox, &c.Packer, &c.SIEM, &c.Backup}
}

// IsLoopback reports whether host (from host:port) only binds loopback.
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
