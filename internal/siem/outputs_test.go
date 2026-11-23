package siem

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/config"
)

type staticCreds map[string]string

func (c staticCreds) Get(_ context.Context, output, field string) (string, error) {
	return c[output+":"+field], nil
}

func testEntry() auditlog.Entry {
	return auditlog.Entry{
		Event: audit.Event{
			ID: "evt1", Time: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC), Actor: "alice", ActorID: "u1",
			Action: "image.build.start", Target: "job:42", Outcome: audit.OutcomeSuccess,
			SourceIP: "192.0.2.10", UserAgent: "test", RequestID: "req1",
			Details: map[string]any{"template": "ubuntu", "password": "hunter2"},
		},
		Seq: 7, Hash: "abc",
	}
}

// newTestManager builds a manager for a single output.
func newTestManager(t *testing.T, o config.SIEMOutput, creds Credentials) *Manager {
	t.Helper()
	cfg, _ := outputCfg(t, o)
	m, err := NewManager(cfg, creds, Options{Host: "pi-host", Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	return m
}

var rfc5424 = regexp.MustCompile(`^<(\d+)>1 (\S+) pi-host perfectimage \d+ (audit|log) (\[[^\]]*\]) (.*)$`)

func checkSyslog(t *testing.T, msg string, wantPRI string, wantCEF bool) {
	t.Helper()
	m := rfc5424.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("not RFC 5424: %q", msg)
	}
	if m[1] != wantPRI {
		t.Fatalf("PRI %s want %s", m[1], wantPRI)
	}
	if _, err := time.Parse(time.RFC3339Nano, m[2]); err != nil {
		t.Fatalf("timestamp %q: %v", m[2], err)
	}
	if !strings.Contains(m[4], `action="image.build.start"`) {
		t.Fatalf("structured data %q", m[4])
	}
	if wantCEF {
		if !strings.HasPrefix(m[5], "CEF:0|PerfectImage|PerfectImage|1.2.3|image.build.start|") {
			t.Fatalf("CEF body %q", m[5])
		}
		return
	}
	var r Record
	if err := json.Unmarshal([]byte(m[5]), &r); err != nil {
		t.Fatalf("JSON body %q: %v", m[5], err)
	}
	if r.ID != "evt1" || r.Fields["actor"] != "alice" {
		t.Fatalf("record %+v", r)
	}
	d := r.Fields["details"].(map[string]any)
	if d["password"] != audit.Redacted || d["template"] != "ubuntu" {
		t.Fatalf("details not redacted: %v", d)
	}
}

// readOctetCounted reads one RFC 6587 octet-counted frame.
func readOctetCounted(br *bufio.Reader) (string, error) {
	n, err := br.ReadString(' ')
	if err != nil {
		return "", err
	}
	size, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	_, err = io.ReadFull(br, buf)
	return string(buf), err
}

func TestSyslogOutputs(t *testing.T) {
	pki := newPKI(t)
	// local0 (16*8) + notice (5) = 133
	tests := []struct {
		name    string
		network string
		typ     string
		cef     bool
	}{
		{"udp", "udp", config.SIEMTypeSyslog, false},
		{"tcp", "tcp", config.SIEMTypeSyslog, false},
		{"tls", "tls", config.SIEMTypeSyslog, false},
		{"cef over tcp", "tcp", config.SIEMTypeCEF, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan string, 10)
			var addr string
			switch tt.network {
			case "udp":
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				addr = pc.LocalAddr().String()
				go func() {
					buf := make([]byte, 65536)
					for {
						n, _, err := pc.ReadFrom(buf)
						if err != nil {
							return
						}
						got <- string(buf[:n])
					}
				}()
			default:
				var ln net.Listener
				var err error
				if tt.network == "tls" {
					ln, err = tls.Listen("tcp", "127.0.0.1:0", pki.serverTLS(t))
				} else {
					ln, err = net.Listen("tcp", "127.0.0.1:0")
				}
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				addr = ln.Addr().String()
				go func() {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					br := bufio.NewReader(c)
					for {
						msg, err := readOctetCounted(br)
						if err != nil {
							return
						}
						got <- msg
					}
				}()
			}
			o := config.SIEMOutput{Type: tt.typ, Address: tt.network + "://" + addr, Streams: []string{"audit"}}
			if tt.network == "tls" {
				o.CAFile, o.CertFile, o.KeyFile = pki.caFile, pki.clientCert, pki.clientKey
			}
			m := newTestManager(t, o, nil)
			m.PublishAudit([]auditlog.Entry{testEntry(), testEntry()})
			for range 2 {
				select {
				case msg := <-got:
					checkSyslog(t, msg, "133", tt.cef)
				case <-time.After(5 * time.Second):
					t.Fatalf("no syslog message; status %+v", m.Statuses())
				}
			}
			waitFor(t, "sent counter", func() bool { return m.Statuses()[0].Sent == 2 })
		})
	}
}

func TestSyslogTLSRejectsUntrustedServer(t *testing.T) {
	pki := newPKI(t)
	other := newPKI(t) // client trusts a different CA
	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.serverTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeSyslog, Address: "tls://" + ln.Addr().String(),
		CAFile: other.caFile, CertFile: pki.clientCert, KeyFile: pki.clientKey}, nil)
	if err := m.Test(context.Background(), "test", "alice"); err == nil ||
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("want certificate error, got %v", err)
	}
	if st := m.Statuses()[0]; st.Failed != 1 || st.LastError == "" || st.Healthy() {
		t.Fatalf("status %+v", st)
	}
}

type captured struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (c *captured) add(r *http.Request, b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = append(c.reqs, r)
	c.body = append(c.body, b)
}

func (c *captured) n() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}

func (c *captured) get(i int) (*http.Request, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reqs[i], c.body[i]
}

func captureServer(t *testing.T, respond func(w http.ResponseWriter, r *http.Request, body []byte)) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.add(r, b)
		if respond != nil {
			respond(w, r, b)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestSplunkHEC(t *testing.T) {
	srv, c := captureServer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	})
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeSplunkHEC, URL: srv.URL, Index: "sec",
		BatchSize: 3}, staticCreds{"test:token": "hec-token-fake"})
	m.PublishAudit([]auditlog.Entry{testEntry(), testEntry(), testEntry()})
	waitFor(t, "HEC request", func() bool { return c.n() >= 1 })
	r, body := c.get(0)
	if r.URL.Path != "/services/collector/event" || r.Header.Get("Authorization") != "Splunk hec-token-fake" {
		t.Fatalf("request %s %v", r.URL.Path, r.Header)
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	n := 0
	for dec.More() {
		var ev struct {
			Time       float64 `json:"time"`
			Index      string  `json:"index"`
			SourceType string  `json:"sourcetype"`
			Host       string  `json:"host"`
			Event      Record  `json:"event"`
		}
		if err := dec.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		if ev.Index != "sec" || ev.SourceType != "perfectimage:json" || ev.Host != "pi-host" ||
			ev.Time != 1777629600 || ev.Event.Message != "image.build.start" {
			t.Fatalf("event %+v", ev)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("batched %d events, want 3", n)
	}
}

func TestSplunkHECMissingToken(t *testing.T) {
	srv, c := captureServer(t, nil)
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeSplunkHEC, URL: srv.URL}, staticCreds{})
	if err := m.Test(context.Background(), "test", "x"); err == nil || !strings.Contains(err.Error(), "token not set") {
		t.Fatalf("err %v", err)
	}
	if c.n() != 0 {
		t.Fatal("request sent without token")
	}
}

func TestElasticBulk(t *testing.T) {
	tests := []struct {
		name     string
		username string
		creds    staticCreds
		wantAuth string
	}{
		{"api key", "", staticCreds{"test:api_key": "encodedkey"}, "ApiKey encodedkey"},
		{"api key id:secret", "", staticCreds{"test:api_key": "id:secret"},
			"ApiKey " + base64.StdEncoding.EncodeToString([]byte("id:secret"))},
		{"basic", "elastic", staticCreds{"test:password": "pw"},
			"Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:pw"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, c := captureServer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				_, _ = w.Write([]byte(`{"errors":false,"items":[]}`))
			})
			m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeElastic, URL: srv.URL, Username: tt.username}, tt.creds)
			m.PublishAudit([]auditlog.Entry{testEntry()})
			waitFor(t, "bulk request", func() bool { return c.n() >= 1 })
			r, body := c.get(0)
			if r.URL.Path != "/_bulk" || r.Header.Get("Authorization") != tt.wantAuth ||
				r.Header.Get("Content-Type") != "application/x-ndjson" {
				t.Fatalf("request %s %v", r.URL.Path, r.Header)
			}
			lines := strings.Split(strings.TrimSpace(string(body)), "\n")
			if len(lines) != 2 || lines[0] != `{"create":{"_id":"evt1","_index":"perfectimage"}}` {
				t.Fatalf("bulk body %q", body)
			}
			var doc map[string]any
			if err := json.Unmarshal([]byte(lines[1]), &doc); err != nil {
				t.Fatal(err)
			}
			ev := doc["event"].(map[string]any)
			if doc["@timestamp"] != "2026-05-01T10:00:00Z" || ev["action"] != "image.build.start" ||
				ev["outcome"] != "success" || doc["user"].(map[string]any)["name"] != "alice" ||
				doc["source"].(map[string]any)["ip"] != "192.0.2.10" {
				t.Fatalf("ECS doc %v", doc)
			}
			pi := doc["perfectimage"].(map[string]any)
			if pi["details"].(map[string]any)["password"] != audit.Redacted {
				t.Fatalf("details %v", pi)
			}
		})
	}
}

func TestBulkErrors(t *testing.T) {
	tests := []struct {
		body      string
		wantErr   bool
		permanent bool
	}{
		{`{"errors":false}`, false, false},
		{`{"errors":true,"items":[{"create":{"status":409}},{"create":{"status":201}}]}`, false, false},
		{`{"errors":true,"items":[{"create":{"status":429}},{"create":{"status":400}}]}`, true, false},
		{`{"errors":true,"items":[{"create":{"status":400,"error":{"type":"mapper_parsing_exception"}}}]}`, true, true},
		{`not json`, true, false},
	}
	for _, tt := range tests {
		err := bulkErrors([]byte(tt.body))
		if (err != nil) != tt.wantErr || isPermanent(err) != tt.permanent {
			t.Errorf("bulkErrors(%s) = %v (permanent %v)", tt.body, err, isPermanent(err))
		}
	}
}

func TestWebhookSignature(t *testing.T) {
	srv, c := captureServer(t, nil)
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeWebhook, URL: srv.URL + "/hook",
		Headers: map[string]string{"X-Tenant": "lab"}},
		staticCreds{"test:hmac_secret": "s3cr3t-fake", "test:auth_header": "Bearer fake-token"})
	m.PublishAudit([]auditlog.Entry{testEntry()})
	waitFor(t, "webhook request", func() bool { return c.n() >= 1 })
	r, body := c.get(0)
	ts := r.Header.Get(HeaderTimestamp)
	if r.URL.Path != "/hook" || r.Header.Get("X-Tenant") != "lab" || r.Header.Get("Authorization") != "Bearer fake-token" {
		t.Fatalf("headers %v", r.Header)
	}
	if got, want := r.Header.Get(HeaderSignature), Sign("s3cr3t-fake", ts, body); got != want || !strings.HasPrefix(got, "sha256=") {
		t.Fatalf("signature %q want %q", got, want)
	}
	var payload struct {
		Source string   `json:"source"`
		Events []Record `json:"events"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Source != "perfectimage" || len(payload.Events) != 1 {
		t.Fatalf("payload %s: %v", body, err)
	}
}

func TestFileOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out", "events.jsonl")
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeFile, Path: path}, nil)
	m.PublishAudit([]auditlog.Entry{testEntry()})
	rec := slog.NewRecord(time.Now(), slog.LevelWarn, "disk low", 0)
	rec.AddAttrs(slog.String("db_password", "pw"), slog.Int("free_mb", 12))
	m.PublishLog(rec)
	waitFor(t, "file output", func() bool { return m.Statuses()[0].Sent == 2 })
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines %q", lines)
	}
	var r Record
	if err := json.Unmarshal([]byte(lines[1]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindLog || r.Level != "warn" || r.Fields["db_password"] != audit.Redacted || r.Fields["free_mb"] != float64(12) {
		t.Fatalf("log record %+v", r)
	}
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), `"pw"`) {
		t.Fatal("secret leaked to file output")
	}
}
