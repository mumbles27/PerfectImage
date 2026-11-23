package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgon2Params follow the OWASP Password Storage Cheat Sheet
// recommendation for argon2id (m=19 MiB, t=2, p=1).
var DefaultArgon2Params = Argon2Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}

// ErrPasswordMismatch is returned by VerifyPassword for a wrong password.
var ErrPasswordMismatch = errors.New("auth: password mismatch")

// errMalformedHash is returned for hashes that cannot be parsed.
var errMalformedHash = errors.New("auth: malformed password hash")

// HashPassword returns a PHC-format argon2id hash of password.
func HashPassword(password string, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks password against a hash produced by HashPassword.
// needsRehash reports whether the hash uses parameters other than want.
func VerifyPassword(password, encoded string, want Argon2Params) (needsRehash bool, err error) {
	p, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(key)))
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return false, ErrPasswordMismatch
	}
	return p.Memory != want.Memory || p.Iterations != want.Iterations ||
		p.Parallelism != want.Parallelism || uint32(len(key)) != want.KeyLen, nil
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errMalformedHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return p, nil, nil, errMalformedHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, errMalformedHash
	}
	if p.Memory == 0 || p.Memory > 1<<22 || p.Iterations == 0 || p.Iterations > 64 || p.Parallelism == 0 {
		return p, nil, nil, errMalformedHash
	}
	b64 := base64.RawStdEncoding
	salt, err1 := b64.DecodeString(parts[4])
	key, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 {
		return p, nil, nil, errMalformedHash
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}

// MaxPasswordLength bounds the input to the hash function.
const MaxPasswordLength = 256

//go:embed common_passwords.txt
var commonPasswordsTxt string

var commonPasswords = sync.OnceValue(func() map[string]bool {
	m := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(commonPasswordsTxt))
	for sc.Scan() {
		if w := strings.TrimSpace(sc.Text()); w != "" && !strings.HasPrefix(w, "#") {
			m[strings.ToLower(w)] = true
		}
	}
	return m
})

// PasswordPolicy validates new passwords.
type PasswordPolicy struct {
	MinLength int
}

// PolicyError explains why a password was rejected. Its message is safe to
// show to the user (it never contains the password).
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return "password rejected: " + e.Reason }

// Check returns a *PolicyError if password is unacceptable for username.
func (p PasswordPolicy) Check(username, password string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < p.MinLength:
		return &PolicyError{fmt.Sprintf("must be at least %d characters", p.MinLength)}
	case len(password) > MaxPasswordLength:
		return &PolicyError{fmt.Sprintf("must be at most %d bytes", MaxPasswordLength)}
	case strings.TrimSpace(password) == "":
		return &PolicyError{"must not be blank"}
	}
	lower := strings.ToLower(password)
	if commonPasswords()[lower] || commonPasswords()[strings.TrimRight(lower, "0123456789!@#$%^&*?.")] {
		return &PolicyError{"is too common"}
	}
	if u := strings.ToLower(username); len(u) >= 3 && strings.Contains(lower, u) {
		return &PolicyError{"must not contain the username"}
	}
	if distinct(password) < 4 {
		return &PolicyError{"is too repetitive"}
	}
	return nil
}

func distinct(s string) int {
	seen := map[rune]bool{}
	for _, r := range s {
		seen[r] = true
	}
	return len(seen)
}

// GeneratePassword returns a random one-time password (128 bits, base32 in
// dash-separated groups) that satisfies any reasonable policy.
func GeneratePassword() string {
	t := rand.Text() // 26 chars, 130 bits
	var b strings.Builder
	for i, c := range t[:25] {
		if i > 0 && i%5 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(c)
	}
	return b.String()
}
