package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Defaults for Options.
const (
	DefaultTimeout          = 30 * time.Second
	DefaultRetries          = 3
	DefaultTaskPollInterval = 2 * time.Second
	maxResponseBytes        = 32 << 20
)

// Options configures a Client.
type Options struct {
	// Endpoint is the API base, e.g. https://pve.example:8006 or
	// https://pve.example:8006/api2/json. Only https is accepted.
	Endpoint string
	// TokenID is USER@REALM!TOKENID.
	TokenID string
	// Secret is the API token secret (UUID). Never logged.
	Secret string

	// CAPEM is a PEM CA bundle used instead of the system roots.
	CAPEM []byte
	// CAFile is read when CAPEM is empty.
	CAFile string
	// Fingerprint pins the SHA-256 fingerprint of the server's leaf
	// certificate (hex, colons optional). When set, a CA chain is only
	// verified in addition if CAPEM/CAFile is also given.
	Fingerprint string
	// InsecureSkipVerify disables all TLS verification. Lab use only; a
	// warning is logged whenever a client is built with it.
	InsecureSkipVerify bool

	// Timeout bounds each request (default 30s). Uploads are bounded only by
	// the caller's context.
	Timeout time.Duration
	// Retries is the number of extra attempts for idempotent GETs on network
	// errors and 429/502/503/504 (default 3; negative disables).
	Retries int
	// RetryBaseDelay is the first backoff delay (default 250ms).
	RetryBaseDelay time.Duration
	// TaskPollInterval is the WaitTask polling interval (default 2s).
	TaskPollInterval time.Duration

	Logger *slog.Logger
	// Transport overrides the HTTP transport (tests). TLS options are
	// ignored when set.
	Transport http.RoundTripper
}

// Client is a Proxmox VE API client. It is safe for concurrent use.
type Client struct {
	base     string // https://host:port/api2/json
	tokenID  string
	secret   string
	hc       *http.Client
	timeout  time.Duration
	retries  int
	backoff  time.Duration
	taskPoll time.Duration
	log      *slog.Logger
}

// New validates opts and returns a client. It does not contact the server.
func New(opts Options) (*Client, error) {
	base, err := NormalizeEndpoint(opts.Endpoint)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(opts.TokenID, "@") || !strings.Contains(opts.TokenID, "!") {
		return nil, errors.New("proxmox: token id must look like USER@REALM!TOKENID")
	}
	if opts.Secret == "" {
		return nil, errors.New("proxmox: token secret is empty")
	}
	if strings.ContainsAny(opts.TokenID, "\r\n\t =") || strings.ContainsAny(opts.Secret, "\r\n\t ") {
		return nil, errors.New("proxmox: token id or secret contains invalid characters")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Retries == 0 {
		opts.Retries = DefaultRetries
	} else if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.RetryBaseDelay <= 0 {
		opts.RetryBaseDelay = 250 * time.Millisecond
	}
	if opts.TaskPollInterval <= 0 {
		opts.TaskPollInterval = DefaultTaskPollInterval
	}
	log := opts.Logger.With("component", "proxmox", "endpoint", base)
	rt := opts.Transport
	if rt == nil {
		tc, err := TLSConfig(opts.CAPEM, opts.CAFile, opts.Fingerprint, opts.InsecureSkipVerify)
		if err != nil {
			return nil, err
		}
		if opts.InsecureSkipVerify && opts.Fingerprint == "" {
			log.Warn("TLS VERIFICATION DISABLED for Proxmox endpoint: connections are open to " +
				"man-in-the-middle attacks and the API token can be stolen. Pin a CA or fingerprint instead.")
		}
		rt = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       tc,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: opts.Timeout,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   4,
			ForceAttemptHTTP2:     true,
		}
	}
	return &Client{
		base:     base,
		tokenID:  opts.TokenID,
		secret:   opts.Secret,
		hc:       &http.Client{Transport: rt, CheckRedirect: noRedirect},
		timeout:  opts.Timeout,
		retries:  opts.Retries,
		backoff:  opts.RetryBaseDelay,
		taskPoll: opts.TaskPollInterval,
		log:      log,
	}, nil
}

// Never follow redirects: the Authorization header must not leave the
// configured endpoint.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Endpoint returns the normalized API base URL.
func (c *Client) Endpoint() string { return c.base }

// NormalizeEndpoint turns "https://host[:port][/api2/json]" into the API
// base URL "https://host:port/api2/json". Port 8006 is assumed when absent.
func NormalizeEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("proxmox: endpoint is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("proxmox: endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return "", errors.New("proxmox: endpoint must use https")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("proxmox: endpoint must be https://host[:port][/api2/json]")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "8006")
	}
	p := strings.TrimRight(u.Path, "/")
	switch p {
	case "", "/api2/json":
	default:
		return "", fmt.Errorf("proxmox: unexpected endpoint path %q (want /api2/json)", u.Path)
	}
	return "https://" + host + "/api2/json", nil
}

// NormalizeFingerprint returns the canonical upper-case colon-separated form
// of a SHA-256 fingerprint, or an error.
func NormalizeFingerprint(fp string) (string, error) {
	b, err := parseFingerprint(fp)
	if err != nil {
		return "", err
	}
	return FormatFingerprint(b), nil
}

// FormatFingerprint formats raw digest bytes as AA:BB:...
func FormatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func parseFingerprint(fp string) ([]byte, error) {
	s := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(fp))
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("proxmox: fingerprint must be a SHA-256 hex digest (64 hex chars, colons optional)")
	}
	return b, nil
}

// TLSConfig builds the client TLS configuration:
//
//   - default: system roots, full verification
//   - caPEM/caFile: only that CA bundle is trusted, full verification
//   - fingerprint: the leaf certificate's SHA-256 must match (constant-time);
//     the chain is verified as well when a CA is also given
//   - insecure (without fingerprint): no verification at all
func TLSConfig(caPEM []byte, caFile, fingerprint string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) == 0 && caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("proxmox: read CA file: %w", err)
		}
		caPEM = b
	}
	var pool *x509.CertPool
	if len(bytes.TrimSpace(caPEM)) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("proxmox: CA bundle contains no PEM certificates")
		}
		cfg.RootCAs = pool
	}
	if fingerprint != "" {
		want, err := parseFingerprint(fingerprint)
		if err != nil {
			return nil, err
		}
		// Standard verification is replaced by VerifyConnection, which
		// always checks the pin and, with a CA, also the chain + hostname.
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrTLSPin
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("%w (server presented %s)", ErrTLSPin, FormatFingerprint(got[:]))
			}
			if pool == nil {
				return nil
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName: cs.ServerName, Roots: pool, Intermediates: inter,
			})
			return err
		}
		return cfg, nil
	}
	if insecure {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

// envelope is the PVE response wrapper.
type envelope struct {
	Data    json.RawMessage   `json:"data"`
	Message string            `json:"message"`
	Errors  map[string]string `json:"errors"`
}

// get performs an idempotent GET (retried) and decodes data into out.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, q, out)
}

func (c *Client) post(ctx context.Context, path string, form url.Values, out any) error {
	return c.do(ctx, http.MethodPost, path, form, out)
}

func (c *Client) put(ctx context.Context, path string, form url.Values, out any) error {
	return c.do(ctx, http.MethodPut, path, form, out)
}

func (c *Client) delete(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodDelete, path, q, out)
}

// do sends a request with params in the query (GET/DELETE) or as a form
// body (POST/PUT). Only GETs are retried.
func (c *Client) do(ctx context.Context, method, path string, params url.Values, out any) error {
	attempts := 1
	if method == http.MethodGet {
		attempts += c.retries
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			d := c.backoff << (i - 1)
			if d > 5*time.Second {
				d = 5 * time.Second
			}
			d += time.Duration(rand.Int64N(int64(d)/2 + 1))
			c.log.Debug("retrying proxmox request", "method", method, "path", path, "attempt", i+1, "delay", d, "err", err)
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		var body io.Reader
		var ctype string
		u := c.base + path
		if method == http.MethodGet || method == http.MethodDelete {
			if len(params) > 0 {
				u += "?" + params.Encode()
			}
		} else {
			body = strings.NewReader(params.Encode())
			ctype = "application/x-www-form-urlencoded"
		}
		err = c.send(ctx, method, path, u, body, ctype, c.timeout, out)
		if err == nil || !retryable(ctx, err) {
			return err
		}
	}
	return err
}

func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Temporary()
	}
	// TLS / certificate failures are permanent.
	var certErr *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if errors.Is(err, ErrTLSPin) || errors.As(err, &certErr) || errors.As(err, &unknown) || errors.As(err, &hostErr) {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

// send performs one HTTP exchange. timeout <= 0 means no per-request bound.
func (c *Client) send(ctx context.Context, method, path, u string, body io.Reader, ctype string, timeout time.Duration, out any) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("proxmox: build request: %w", err)
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.tokenID+"="+c.secret)
	req.Header.Set("Accept", "application/json")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		// *url.Error includes the URL (no credentials: they are in a header).
		return fmt.Errorf("proxmox: %s %s: %w", method, path, unwrapURLError(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	c.log.Debug("proxmox request", "method", method, "path", path, "status", resp.StatusCode,
		"duration", time.Since(start).Round(time.Millisecond))
	if err != nil {
		return fmt.Errorf("proxmox: %s %s: read body: %w", method, path, err)
	}
	var env envelope
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := env.Message
		if msg == "" {
			// PVE puts the error text in the reason phrase.
			_, msg, _ = strings.Cut(resp.Status, " ")
		}
		return &APIError{Method: method, Path: path, StatusCode: resp.StatusCode,
			Message: strings.TrimSpace(msg), Errors: env.Errors}
	}
	if out == nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("proxmox: %s %s: decode: %w", method, path, err)
	}
	return nil
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// seg escapes one path segment.
func seg(s string) string { return url.PathEscape(s) }

func vmPath(node string, vmid int) string {
	return fmt.Sprintf("/nodes/%s/qemu/%d", seg(node), vmid)
}
