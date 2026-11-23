// Package tlsutil generates and loads TLS material.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Validity of generated certificates and the renewal window.
const (
	Validity     = 2 * 365 * 24 * time.Hour
	RenewBefore  = 30 * 24 * time.Hour
	CertFileName = "selfsigned.crt"
	KeyFileName  = "selfsigned.key"
)

// EnsureSelfSigned returns paths to a self-signed certificate and key in dir,
// generating them if missing, unparsable or expiring within RenewBefore.
// hosts are DNS names or IPs added as SANs alongside the machine hostname,
// localhost, 127.0.0.1 and ::1. The key file is written with mode 0600.
func EnsureSelfSigned(dir string, hosts []string, now time.Time) (certFile, keyFile string, generated bool, err error) {
	certFile = filepath.Join(dir, CertFileName)
	keyFile = filepath.Join(dir, KeyFileName)
	if valid(certFile, keyFile, now) {
		return certFile, keyFile, false, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", false, err
	}
	certPEM, keyPEM, err := Generate(hosts, now)
	if err != nil {
		return "", "", false, err
	}
	if err := writeAtomic(keyFile, keyPEM, 0o600); err != nil {
		return "", "", false, err
	}
	if err := writeAtomic(certFile, certPEM, 0o644); err != nil {
		return "", "", false, err
	}
	return certFile, keyFile, true, nil
}

func valid(certFile, keyFile string, now time.Time) bool {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	return now.Add(RenewBefore).Before(c.NotAfter)
}

// Generate creates a PEM-encoded ECDSA P-256 self-signed certificate and key.
func Generate(hosts []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	hostname, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "PerfectImage", Organization: []string{"PerfectImage (self-signed)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(Validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	all := append([]string{"localhost", "127.0.0.1", "::1"}, hosts...)
	if hostname != "" {
		all = append(all, hostname)
	}
	seen := map[string]bool{}
	for _, h := range all {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	// CreateTemp uses 0600; widen if requested. Best-effort on Windows.
	_ = tmp.Chmod(perm)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("tlsutil: write %s: %w", path, err)
	}
	return nil
}
