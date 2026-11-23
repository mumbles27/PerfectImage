package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testSealer(t *testing.T) *AESGCM {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewAESGCMKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewAESGCM(make([]byte, n)); err == nil {
			t.Errorf("key size %d accepted", n)
		}
	}
}

func TestSealOpen(t *testing.T) {
	s := testSealer(t)
	tests := []struct {
		name      string
		plain     []byte
		aad       []byte
		openAAD   []byte
		tamper    func([]byte) []byte
		wantError bool
	}{
		{name: "roundtrip", plain: []byte("token-value"), aad: []byte("a"), openAAD: []byte("a")},
		{name: "empty plaintext", plain: []byte{}, aad: nil, openAAD: nil},
		{name: "aad mismatch", plain: []byte("x"), aad: []byte("a"), openAAD: []byte("b"), wantError: true},
		{name: "bit flip", plain: []byte("x"), tamper: func(b []byte) []byte { b[len(b)-1] ^= 1; return b }, wantError: true},
		{name: "truncated", plain: []byte("x"), tamper: func(b []byte) []byte { return b[:5] }, wantError: true},
		{name: "bad version", plain: []byte("x"), tamper: func(b []byte) []byte { b[0] = 9; return b }, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := s.Seal(tt.plain, tt.aad)
			if err != nil {
				t.Fatal(err)
			}
			if len(tt.plain) >= 8 && bytes.Contains(ct, tt.plain) { // short values can occur by chance
				t.Fatal("ciphertext contains plaintext")
			}
			if tt.tamper != nil {
				ct = tt.tamper(ct)
			}
			pt, err := s.Open(ct, tt.openAAD)
			if tt.wantError {
				if !errors.Is(err, ErrDecrypt) {
					t.Fatalf("err = %v, want ErrDecrypt", err)
				}
				return
			}
			if err != nil || !bytes.Equal(pt, tt.plain) {
				t.Fatalf("Open = %q, %v", pt, err)
			}
		})
	}
}

func TestSealNonceUnique(t *testing.T) {
	s := testSealer(t)
	a, _ := s.Seal([]byte("same"), nil)
	b, _ := s.Seal([]byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("identical ciphertexts for repeated Seal")
	}
}

func TestEncryptDecryptString(t *testing.T) {
	s := testSealer(t)
	tok, err := EncryptString(s, "hunter2", "user:1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptString(s, tok, "user:1"); err != nil || got != "hunter2" {
		t.Fatalf("DecryptString = %q, %v", got, err)
	}
	for _, bad := range []string{"", "plain", "pi1:!!!", "pi1:AAAA"} {
		if _, err := DecryptString(s, bad, "user:1"); !errors.Is(err, ErrDecrypt) {
			t.Errorf("DecryptString(%q) err = %v", bad, err)
		}
	}
	if _, err := DecryptString(testSealer(t), tok, "user:1"); !errors.Is(err, ErrDecrypt) {
		t.Error("decrypted with wrong key")
	}
}

func TestLoadOrCreateMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", DefaultKeyFileName)
	k1, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != KeySize {
		t.Fatalf("key len %d", len(k1))
	}
	k2, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("key changed between loads")
	}
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perms = %v, want 0600", fi.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateMasterKey(path); err == nil {
		t.Error("accepted world-readable key file")
	}
}

func TestOpenSealer(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultKeyFileName)
	s1, err := OpenSealer(path)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := EncryptString(s1, "v", "aad")
	s2, err := OpenSealer(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptString(s2, tok, "aad"); err != nil || got != "v" {
		t.Fatalf("reopened sealer cannot decrypt: %q %v", got, err)
	}
}
