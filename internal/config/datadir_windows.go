//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// DefaultDataDir returns %ProgramData%\PerfectImage.
func DefaultDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "PerfectImage")
}

// DefaultConfigPath returns %ProgramData%\PerfectImage\config.yaml.
func DefaultConfigPath() string { return filepath.Join(DefaultDataDir(), "config.yaml") }
