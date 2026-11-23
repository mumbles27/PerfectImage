package siem

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/config"
)

// outputCfg returns a defaulted output config for tests.
func outputCfg(t *testing.T, o config.SIEMOutput) (config.SIEMConfig, config.SIEMOutput) {
	t.Helper()
	if o.Name == "" {
		o.Name = "test"
	}
	if o.FlushInterval == 0 {
		o.FlushInterval = 10 * time.Millisecond
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 50 * time.Millisecond
	}
	c := config.SIEMConfig{Outputs: []config.SIEMOutput{o}, SpillDir: filepath.Join(t.TempDir(), "spill")}
	c.ApplyDefaults(&config.Config{DataDir: t.TempDir()})
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c, c.Outputs[0]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func shortBackoff(t *testing.T) {
	old := baseBackoff
	baseBackoff = 5 * time.Millisecond
	t.Cleanup(func() { baseBackoff = old })
}

type testPKI struct {
	caFile, serverCert, serverKey, clientCert, clientKey string
	caPool                                               *x509.CertPool
}

// newPKI writes a throwaway CA, a server certificate for 127.0.0.1 and a
// client certificate into a temp dir.
func newPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	leaf := func(name string, serial int64, client bool) (string, string) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if client {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalECPrivateKey(k)
		return write(name+".crt", "CERTIFICATE", der), write(name+".key", "EC PRIVATE KEY", kd)
	}
	p := testPKI{caFile: write("ca.crt", "CERTIFICATE", caDER), caPool: x509.NewCertPool()}
	p.caPool.AddCert(ca)
	p.serverCert, p.serverKey = leaf("server", 2, false)
	p.clientCert, p.clientKey = leaf("client", 3, true)
	return p
}

func (p testPKI) serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(p.serverCert, p.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: p.caPool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
}
