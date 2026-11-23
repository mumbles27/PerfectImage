//go:build !windows

package secrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultKeyFileName is the master key file name under DataDir/secrets.
const DefaultKeyFileName = "master.key"

// LoadOrCreateMasterKey reads the raw 32-byte master key from path, creating
// it (mode 0600, parent dir 0700) if it does not exist. It refuses to use a
// key file readable by group or others.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	b, err := readKeyFile(path)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("secrets: create key dir: %w", err)
	}
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) { // lost a race; use the winner's key
			return readKeyFile(path)
		}
		return nil, fmt.Errorf("secrets: create key file: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("secrets: write key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func readKeyFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secrets: key file %s has insecure permissions %v (want 0600)", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("secrets: key file %s: want %d bytes, got %d", path, KeySize, len(b))
	}
	return b, nil
}
