//go:build !windows

package config

// DefaultDataDir returns /var/lib/perfectimage.
func DefaultDataDir() string { return "/var/lib/perfectimage" }

// DefaultConfigPath returns /etc/perfectimage/config.yaml.
func DefaultConfigPath() string { return "/etc/perfectimage/config.yaml" }
