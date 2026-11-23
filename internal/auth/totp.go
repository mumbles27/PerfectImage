package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; HMAC-SHA1 is not affected by SHA-1 collisions.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image/png"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

// TOTP parameters (RFC 6238 defaults understood by every authenticator app).
const (
	totpDigits = 6
	totpPeriod = 30 // seconds
	totpSkew   = 1  // accepted steps before/after the current one
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret, base32-encoded.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

// totpCode computes the RFC 4226 HOTP value for step.
func totpCode(key []byte, step uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], step)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// TOTPCode returns the code for secret at time t (exported for tests and
// tooling).
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("auth: bad TOTP secret: %w", err)
	}
	return totpCode(key, uint64(t.Unix())/totpPeriod), nil
}

// ValidateTOTP checks code against secret at time t, allowing ±totpSkew
// steps. It returns the matched step, which must be greater than lastStep
// (replay protection); ok is false otherwise.
func ValidateTOTP(secret, code string, t time.Time, lastStep int64) (step int64, ok bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	now := int64(t.Unix()) / totpPeriod
	matched := int64(-1)
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		s := now + d
		if s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpCode(key, uint64(s))), []byte(code)) == 1 && s > lastStep {
			matched = s
		}
	}
	return matched, matched >= 0
}

// TOTPURI returns the otpauth:// provisioning URI.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// QRCodeDataURI renders text as a QR code PNG data: URI (allowed by the CSP
// img-src directive). Pure Go, no external service.
func QRCodeDataURI(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	c.Scale = 6
	var buf bytes.Buffer
	if err := png.Encode(&buf, c.Image()); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// RecoveryCodeCount is how many recovery codes are generated at once.
const RecoveryCodeCount = 10

// NewRecoveryCodes returns RecoveryCodeCount random codes (80 bits each),
// formatted as xxxx-xxxx-xxxx-xxxx.
func NewRecoveryCodes() []string {
	out := make([]string, RecoveryCodeCount)
	for i := range out {
		b := make([]byte, 10)
		_, _ = rand.Read(b)
		s := strings.ToLower(b32.EncodeToString(b)) // 16 chars
		out[i] = s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
	}
	return out
}

// normalizeRecoveryCode strips separators and case.
func normalizeRecoveryCode(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	return strings.NewReplacer("-", "", " ", "").Replace(c)
}

// hashRecoveryCode hashes a (high-entropy) recovery code for storage.
func hashRecoveryCode(c string) string {
	sum := sha256.Sum256([]byte("pi-recovery:" + normalizeRecoveryCode(c)))
	return hex.EncodeToString(sum[:])
}
