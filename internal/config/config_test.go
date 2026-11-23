package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(""))
	if err != nil {
		t.Fatalf("Parse empty: %v", err)
	}
	if c.DataDir != DefaultDataDir() {
		t.Errorf("DataDir = %q", c.DataDir)
	}
	if c.Server.Listen != ":8443" || c.Jobs.Workers != 2 || c.Log.Level != "info" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if want := filepath.Join(c.DataDir, "perfectimage.db"); c.Database.Path != want {
		t.Errorf("Database.Path = %q, want %q", c.Database.Path, want)
	}
	if !c.Server.TLS.AutoTLS() {
		t.Error("expected auto TLS by default")
	}
	if c.Auth.SessionTTL != 8*time.Hour || c.Backup.Retention != 7 {
		t.Error("section defaults not applied")
	}
}

func TestParseValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"ok", "data_dir: ./data\nserver: {listen: '127.0.0.1:9000'}\n", ""},
		{"unknown key", "bogus: 1\n", "field bogus not found"},
		{"bad listen", "server: {listen: 'nope'}\n", "server.listen"},
		{"half tls", "server: {tls: {cert_file: a.pem}}\n", "must be set together"},
		{"tls disable non-loopback", "server: {listen: '0.0.0.0:80', tls: {disable: true}}\n", "tls.disable"},
		{"tls disable loopback", "server: {listen: '127.0.0.1:80', tls: {disable: true}}\n", ""},
		{"bad level", "log: {level: loud}\n", "log.level"},
		{"workers", "jobs: {workers: 100}\n", "jobs.workers"},
		{"dev allow all public", "auth: {dev_allow_all: true}\n", "dev_allow_all"},
		{"dev allow all loopback", "server: {listen: 'localhost:8443'}\nauth: {dev_allow_all: true}\n", ""},
		{"relative data dir", "data_dir: data\n", "data_dir"},
		{"proxmox missing endpoint", "proxmox: {clusters: [{name: a}]}\n", "proxmox.clusters[0]"},
		{"durations", "server: {shutdown_timeout: 5s}\njobs: {poll_interval: 250ms}\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadExampleConfig(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("example config invalid: %v", err)
	}
	if c.Path() == "" {
		t.Error("Path not recorded")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pi.yaml")
	if err := os.WriteFile(path, []byte("data_dir: ./data\nlog: {file: '-'}\ncatalog: {dirs: [cat]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "data"); c.DataDir != want {
		t.Errorf("DataDir = %q, want %q", c.DataDir, want)
	}
	if want := filepath.Join(dir, "data", "perfectimage.db"); c.Database.Path != want {
		t.Errorf("Database.Path = %q, want %q", c.Database.Path, want)
	}
	if c.Log.File != "-" || c.Catalog.Dirs[0] != filepath.Join(dir, "cat") {
		t.Errorf("Log.File=%q Catalog=%v", c.Log.File, c.Catalog.Dirs)
	}
}
