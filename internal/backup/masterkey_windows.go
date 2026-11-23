//go:build windows

package backup

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiEntropy must match internal/secrets (keyfile_windows.go) so the
// service can unprotect the restored key.
// TODO(ops): replace with an exported secrets.StoreMasterKey once core adds it.
var dpapiEntropy = []byte("PerfectImage master key v1")

// writeMasterKey protects the key with DPAPI (machine scope), matching
// secrets.LoadOrCreateMasterKey on Windows.
func writeMasterKey(path string, key []byte) error {
	blobOf := func(b []byte) *windows.DataBlob {
		if len(b) == 0 {
			return &windows.DataBlob{}
		}
		return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	}
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN | windows.CRYPTPROTECT_LOCAL_MACHINE)
	if err := windows.CryptProtectData(blobOf(key), nil, blobOf(dpapiEntropy), 0, nil, flags, &out); err != nil {
		return err
	}
	blob := append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
