package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestEnsureSelfSigned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	now := time.Now()
	cert, key, gen, err := EnsureSelfSigned(dir, []string{"pi.example.com", "10.0.0.5"}, now)
	if err != nil || !gen {
		t.Fatalf("first call: gen=%v err=%v", gen, err)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(pair.Certificate[0])
	if !slices.Contains(c.DNSNames, "pi.example.com") || !slices.Contains(c.DNSNames, "localhost") {
		t.Errorf("DNSNames = %v", c.DNSNames)
	}
	if len(c.IPAddresses) < 3 {
		t.Errorf("IPAddresses = %v", c.IPAddresses)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(key)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("key perms %v", fi.Mode().Perm())
		}
	}

	tests := []struct {
		name    string
		now     time.Time
		wantGen bool
	}{
		{"still valid", now.Add(24 * time.Hour), false},
		{"inside renewal window", now.Add(Validity - RenewBefore/2), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, gen, err := EnsureSelfSigned(dir, nil, tt.now)
			if err != nil || gen != tt.wantGen {
				t.Fatalf("gen=%v err=%v, want gen=%v", gen, err, tt.wantGen)
			}
		})
	}
}

func TestEnsureSelfSignedCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CertFileName), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, gen, err := EnsureSelfSigned(dir, nil, time.Now()); err != nil || !gen {
		t.Fatalf("corrupt cert not regenerated: gen=%v err=%v", gen, err)
	}
}
