package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/config"
)

// maxUDPMessage keeps datagrams under the IPv4 UDP payload limit.
const maxUDPMessage = 65000

// tlsConfig builds a client TLS config from an output's CA/cert settings.
func tlsConfig(c config.SIEMOutput, defaultServerName string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ServerName, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in lab setting
	if tc.ServerName == "" {
		tc.ServerName = defaultServerName
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file contains no PEM certificates")
		}
		tc.RootCAs = pool
	}
	if c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

// syslogTransport sends RFC 5424 messages over UDP (one per datagram), TCP
// or TLS (RFC 6587 octet counting). The MSG part is the record as JSON, or a
// CEF event for type "cef".
type syslogTransport struct {
	network  string // udp, tcp, tls
	addr     string
	tls      *tls.Config
	facility int
	appName  string
	cef      bool
	version  string

	mu   sync.Mutex
	conn net.Conn
}

func newSyslogTransport(c config.SIEMOutput, version string) (*syslogTransport, error) {
	scheme, addr, ok := strings.Cut(c.Address, "://")
	if !ok {
		return nil, fmt.Errorf("address %q: want udp://, tcp:// or tls://host:port", c.Address)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("address %q: %w", c.Address, err)
	}
	fac, err := parseFacility(c.Facility)
	if err != nil {
		return nil, err
	}
	t := &syslogTransport{network: scheme, addr: addr, facility: fac, appName: c.AppName,
		cef: c.Type == config.SIEMTypeCEF, version: version}
	switch scheme {
	case "udp", "tcp":
	case "tls":
		if t.tls, err = tlsConfig(c, host); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("address %q: unsupported scheme %q", c.Address, scheme)
	}
	return t, nil
}

func (t *syslogTransport) message(r Record) []byte {
	body := jsonBody(r)
	if t.cef {
		body = formatCEF(r, t.version)
	}
	return formatSyslog(r, t.facility, t.appName, body)
}

func (t *syslogTransport) dial(ctx context.Context) (net.Conn, error) {
	if t.conn != nil {
		return t.conn, nil
	}
	var d net.Dialer
	var conn net.Conn
	var err error
	if t.network == "tls" {
		td := tls.Dialer{NetDialer: &d, Config: t.tls}
		conn, err = td.DialContext(ctx, "tcp", t.addr)
	} else {
		conn, err = d.DialContext(ctx, t.network, t.addr)
	}
	if err != nil {
		return nil, err
	}
	t.conn = conn
	return conn, nil
}

// Send implements transport.
func (t *syslogTransport) Send(ctx context.Context, batch []Record) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, err := t.dial(ctx)
	if err != nil {
		return fmt.Errorf("syslog dial %s: %w", t.addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	}
	var buf []byte
	for _, r := range batch {
		msg := t.message(r)
		if t.network == "udp" {
			if len(msg) > maxUDPMessage {
				msg = msg[:maxUDPMessage]
			}
			if _, err := conn.Write(msg); err != nil {
				t.reset()
				return fmt.Errorf("syslog write: %w", err)
			}
			continue
		}
		buf = strconv.AppendInt(buf, int64(len(msg)), 10)
		buf = append(buf, ' ')
		buf = append(buf, msg...)
	}
	if len(buf) > 0 {
		if _, err := conn.Write(buf); err != nil {
			t.reset()
			return fmt.Errorf("syslog write: %w", err)
		}
	}
	return nil
}

func (t *syslogTransport) reset() {
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
}

// Close implements transport.
func (t *syslogTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reset()
	return nil
}
