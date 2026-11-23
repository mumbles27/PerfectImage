package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/config"
)

// Credential fields per output type (set on /settings/siem, sealed in the DB).
const (
	CredHECToken   = "token"
	CredAPIKey     = "api_key"
	CredPassword   = "password"
	CredHMACSecret = "hmac_secret"
	CredAuthHeader = "auth_header"
)

// CredentialFields lists the credentials an output type accepts.
func CredentialFields(typ string) []string {
	switch typ {
	case config.SIEMTypeSplunkHEC:
		return []string{CredHECToken}
	case config.SIEMTypeElastic:
		return []string{CredAPIKey, CredPassword}
	case config.SIEMTypeWebhook:
		return []string{CredHMACSecret, CredAuthHeader}
	}
	return nil
}

// Credentials resolves sealed output credentials at send time ("" if unset),
// so changes on /settings/siem apply without a restart.
type Credentials interface {
	Get(ctx context.Context, output, field string) (string, error)
}

// Webhook signature headers.
const (
	HeaderTimestamp = "X-PerfectImage-Timestamp"
	HeaderSignature = "X-PerfectImage-Signature"
)

// Sign returns the webhook signature "sha256=<hex HMAC-SHA256(secret, ts + "." + body)>".
func Sign(secret, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts))
	m.Write([]byte{'.'})
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

type httpKind int

const (
	kindHEC httpKind = iota
	kindElastic
	kindWebhook
)

// httpTransport implements the Splunk HEC, Elasticsearch/OpenSearch _bulk
// and JSON webhook outputs.
type httpTransport struct {
	kind   httpKind
	cfg    config.SIEMOutput
	url    string
	client *http.Client
	creds  Credentials
}

func newHTTPTransport(c config.SIEMOutput, creds Credentials) (*httpTransport, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("url %q is invalid", c.URL)
	}
	tc, err := tlsConfig(c, "")
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	tr.Proxy = http.ProxyFromEnvironment
	t := &httpTransport{cfg: c, creds: creds, client: &http.Client{
		Transport: tr,
		Timeout:   c.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never forward credentials to a redirect target
		},
	}}
	base := strings.TrimRight(c.URL, "/")
	switch c.Type {
	case config.SIEMTypeSplunkHEC:
		t.kind = kindHEC
		t.url = base
		if !strings.Contains(u.Path, "/services/collector") {
			t.url = base + "/services/collector/event"
		}
	case config.SIEMTypeElastic:
		t.kind = kindElastic
		t.url = base
		if !strings.HasSuffix(u.Path, "/_bulk") {
			t.url = base + "/_bulk"
		}
	case config.SIEMTypeWebhook:
		t.kind = kindWebhook
		t.url = c.URL
	default:
		return nil, fmt.Errorf("type %q is not an HTTP output", c.Type)
	}
	return t, nil
}

func (t *httpTransport) cred(ctx context.Context, field string) (string, error) {
	if t.creds == nil {
		return "", nil
	}
	v, err := t.creds.Get(ctx, t.cfg.Name, field)
	if err != nil {
		return "", fmt.Errorf("load credential %s: %w", field, err)
	}
	return v, nil
}

// Send implements transport.
func (t *httpTransport) Send(ctx context.Context, batch []Record) error {
	var body []byte
	var ctype string
	switch t.kind {
	case kindHEC:
		body, ctype = t.hecBody(batch), "application/json"
	case kindElastic:
		body, ctype = t.bulkBody(batch), "application/x-ndjson"
	case kindWebhook:
		b, err := json.Marshal(map[string]any{"source": "perfectimage", "sent_at": time.Now().UTC(), "events": batch})
		if err != nil {
			return permanent(err)
		}
		body, ctype = b, "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return permanent(err)
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "PerfectImage-SIEM/1")
	for _, k := range sortedKeys(t.cfg.Headers) {
		req.Header.Set(k, t.cfg.Headers[k])
	}
	if err := t.authorize(ctx, req, body); err != nil {
		return err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", redactURL(t.url), err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := classifyHTTP(resp.StatusCode, respBody); err != nil {
		return err
	}
	if t.kind == kindElastic {
		return bulkErrors(respBody)
	}
	return nil
}

func (t *httpTransport) authorize(ctx context.Context, req *http.Request, body []byte) error {
	switch t.kind {
	case kindHEC:
		tok, err := t.cred(ctx, CredHECToken)
		if err != nil {
			return err
		}
		if tok == "" {
			return errors.New("splunk HEC token not set (configure it on /settings/siem)")
		}
		req.Header.Set("Authorization", "Splunk "+tok)
	case kindElastic:
		if t.cfg.Username != "" {
			pw, err := t.cred(ctx, CredPassword)
			if err != nil {
				return err
			}
			req.SetBasicAuth(t.cfg.Username, pw)
			break
		}
		key, err := t.cred(ctx, CredAPIKey)
		if err != nil {
			return err
		}
		if key == "" {
			return errors.New("elastic API key not set (configure it on /settings/siem or set username for basic auth)")
		}
		// Accept either the encoded key or "id:api_key".
		if strings.Contains(key, ":") {
			key = base64.StdEncoding.EncodeToString([]byte(key))
		}
		req.Header.Set("Authorization", "ApiKey "+key)
	case kindWebhook:
		if h, err := t.cred(ctx, CredAuthHeader); err != nil {
			return err
		} else if h != "" {
			req.Header.Set("Authorization", h)
		}
		secret, err := t.cred(ctx, CredHMACSecret)
		if err != nil {
			return err
		}
		if secret != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			req.Header.Set(HeaderTimestamp, ts)
			req.Header.Set(HeaderSignature, Sign(secret, ts, body))
		}
	}
	return nil
}

func (t *httpTransport) hecBody(batch []Record) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range batch {
		ev := map[string]any{
			"time":       float64(r.Time.UnixMilli()) / 1000,
			"source":     "perfectimage:" + r.Kind,
			"sourcetype": t.cfg.SourceType,
			"event":      r,
		}
		if r.Host != "" {
			ev["host"] = r.Host
		}
		if t.cfg.Index != "" {
			ev["index"] = t.cfg.Index
		}
		_ = enc.Encode(ev)
	}
	return buf.Bytes()
}

func (t *httpTransport) bulkBody(batch []Record) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range batch {
		// "create" with the record ID makes retries idempotent (409 = already indexed)
		// and works for data streams.
		_ = enc.Encode(map[string]any{"create": map[string]any{"_index": t.cfg.Index, "_id": r.ID}})
		_ = enc.Encode(ecsDocument(r))
	}
	return buf.Bytes()
}

// classifyHTTP maps a status code to nil, a retryable or a permanent error.
func classifyHTTP(code int, body []byte) error {
	if code >= 200 && code < 300 {
		return nil
	}
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}
	err := fmt.Errorf("http %d: %s", code, snippet)
	switch {
	case code == http.StatusUnauthorized, code == http.StatusForbidden, code == http.StatusNotFound,
		code == http.StatusRequestTimeout, code == http.StatusTooManyRequests, code >= 500, code < 200:
		// Auth and routing problems are retried so data survives until the
		// operator fixes the credential or endpoint.
		return err
	default:
		return permanent(err)
	}
}

// bulkErrors inspects a _bulk response for per-item failures.
func bulkErrors(body []byte) error {
	var resp struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  any `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode _bulk response: %w", err)
	}
	if !resp.Errors {
		return nil
	}
	var retry, rejected int
	var first any
	for _, it := range resp.Items {
		for _, r := range it {
			switch {
			case r.Status < 300, r.Status == http.StatusConflict:
			case r.Status == http.StatusTooManyRequests || r.Status >= 500:
				retry++
			default:
				rejected++
				if first == nil {
					first = r.Error
				}
			}
		}
	}
	if retry > 0 {
		return fmt.Errorf("_bulk: %d item(s) need retry", retry)
	}
	if rejected > 0 {
		return permanent(fmt.Errorf("_bulk: %d item(s) rejected: %v", rejected, first))
	}
	return nil
}

func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "(invalid url)"
	}
	return u.Redacted()
}

// Close implements transport.
func (t *httpTransport) Close() error {
	t.client.CloseIdleConnections()
	return nil
}
