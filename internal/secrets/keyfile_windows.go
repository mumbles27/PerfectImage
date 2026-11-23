//go:build windows

package secrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DefaultKeyFileName is the DPAPI-protected master key file under DataDir\secrets.
const DefaultKeyFileName = "master.key.dpapi"

// dpapiEntropy is fixed, non-secret additional entropy that scopes the blob to
// PerfectImage.
var dpapiEntropy = []byte("PerfectImage master key v1")

// LoadOrCreateMasterKey reads the DPAPI-protected master key from path,
// creating it if missing. The key is protected with machine scope
// (CRYPTPROTECT_LOCAL_MACHINE) so both the service (LocalSystem) and
// administrator CLI invocations (backup/restore) can unseal it; the file
// itself lives under %ProgramData%\PerfectImage which the installer locks
// down to SYSTEM and Administrators.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err == nil {
		key, err := dpapiUnprotect(blob)
		if err != nil {
			return nil, fmt.Errorf("secrets: unprotect %s: %w", path, err)
		}
		if len(key) != KeySize {
			return nil, fmt.Errorf("secrets: key file %s: want %d bytes, got %d", path, KeySize, len(key))
		}
		return key, nil
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
	blob, err = dpapiProtect(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: protect key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return LoadOrCreateMasterKey(path)
		}
		return nil, err
	}
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func dpapiProtect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN | windows.CRYPTPROTECT_LOCAL_MACHINE)
	if err := windows.CryptProtectData(blobOf(plain), nil, blobOf(dpapiEntropy), 0, nil, flags, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blobOf(blob), nil, blobOf(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}
