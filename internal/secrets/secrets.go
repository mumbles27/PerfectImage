// Package secrets seals sensitive values (API tokens, passwords) at rest with
// AES-256-GCM. The 32-byte master key is protected by DPAPI on Windows and by
// a 0600 key file on other platforms (see LoadOrCreateMasterKey).
//
// Typical use:
//
//	ct, err := sealer.Seal(plaintext, []byte("proxmox:cluster-a:token"))
//	pt, err := sealer.Open(ct, []byte("proxmox:cluster-a:token"))
//
// The additional data (aad) binds a ciphertext to its purpose so values cannot
// be swapped between rows; use a stable, non-secret identifier.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the master key length in bytes (AES-256).
const KeySize = 32

const (
	formatVersion byte = 1
	stringPrefix       = "pi1:"
)

// ErrDecrypt is returned when a ciphertext is malformed or fails authentication.
var ErrDecrypt = errors.New("secrets: decryption failed")

// Sealer encrypts and authenticates small secrets.
type Sealer interface {
	// Seal encrypts plaintext, binding it to aad.
	Seal(plaintext, aad []byte) ([]byte, error)
	// Open decrypts ciphertext produced by Seal with the same aad.
	Open(ciphertext, aad []byte) ([]byte, error)
}

// AESGCM is a Sealer using AES-256-GCM with random 96-bit nonces.
// Ciphertext layout: version(1) || nonce(12) || sealed.
type AESGCM struct {
	aead cipher.AEAD
}

var _ Sealer = (*AESGCM)(nil)

// NewAESGCM returns a Sealer for a 32-byte key.
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESGCM{aead: aead}, nil
}

// Seal implements Sealer.
func (s *AESGCM) Seal(plaintext, aad []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	out := make([]byte, 1+ns, 1+ns+len(plaintext)+s.aead.Overhead())
	out[0] = formatVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return nil, fmt.Errorf("secrets: nonce: %w", err)
	}
	return s.aead.Seal(out, out[1:1+ns], plaintext, aad), nil
}

// Open implements Sealer.
func (s *AESGCM) Open(ciphertext, aad []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(ciphertext) < 1+ns+s.aead.Overhead() || ciphertext[0] != formatVersion {
		return nil, ErrDecrypt
	}
	pt, err := s.aead.Open(nil, ciphertext[1:1+ns], ciphertext[1+ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// EncryptString seals plaintext and returns a printable "pi1:<base64>" token
// suitable for TEXT columns.
func EncryptString(s Sealer, plaintext, aad string) (string, error) {
	ct, err := s.Seal([]byte(plaintext), []byte(aad))
	if err != nil {
		return "", err
	}
	return stringPrefix + base64.RawStdEncoding.EncodeToString(ct), nil
}

// DecryptString reverses EncryptString.
func DecryptString(s Sealer, token, aad string) (string, error) {
	rest, ok := strings.CutPrefix(token, stringPrefix)
	if !ok {
		return "", ErrDecrypt
	}
	ct, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil {
		return "", ErrDecrypt
	}
	pt, err := s.Open(ct, []byte(aad))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// NewKey returns a fresh random master key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// OpenSealer loads (or creates) the master key at keyFile and returns a Sealer.
func OpenSealer(keyFile string) (*AESGCM, error) {
	key, err := LoadOrCreateMasterKey(keyFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return NewAESGCM(key)
}
