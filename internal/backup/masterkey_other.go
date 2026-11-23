//go:build !windows

package backup

import "os"

// writeMasterKey stores the raw key as a 0600 file, matching
// secrets.LoadOrCreateMasterKey on Linux.
func writeMasterKey(path string, key []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
