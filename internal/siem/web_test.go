package siem

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
	"github.com/mumbles27/PerfectImage/internal/web"
)

type memAudit struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (m *memAudit) Record(_ context.Context, e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evs = append(m.evs, e)
	return nil
}

func (m *memAudit) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, e := range m.evs {
		out = append(out, e.Action+":"+string(e.Outcome))
	}
	return out
}

func TestSettingsPage(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	key, _ := secrets.NewKey()
	sealer, _ := secrets.NewAESGCM(key)
	creds := &dbCredentials{db: db, sealer: sealer}

	hec, c := captureServer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) { _, _ = w.Write([]byte(`{"code":0}`)) })
	cfg, _ := outputCfg(t, config.SIEMOutput{Name: "splunk", Type: config.SIEMTypeSplunkHEC, URL: hec.URL})
	m, err := NewManager(cfg, creds, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(ctx)

	rec := &memAudit{}
	srv := web.NewServer(web.Options{Audit: rec})
	srv.SetAuthenticator(auth.DevAllowAll{})
	srv.SetAuthorizer(auth.DevAllowAll{})
	srv.AddModule(&module{m: m, creds: creds})
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		var body *strings.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("HX-Request", "true")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := do("GET", "/settings/siem", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "splunk") ||
		!strings.Contains(w.Body.String(), "(not set)") {
		t.Fatalf("page %d %s", w.Code, w.Body.String())
	}
	// Test fails without a token.
	if w := do("POST", "/settings/siem/splunk/test", nil); !strings.Contains(w.Body.String(), "token not set") {
		t.Fatalf("test without token: %s", w.Body.String())
	}
	if w := do("POST", "/settings/siem/splunk/credential", url.Values{"field": {"token"}, "value": {"fake-hec-token"}}); w.Code != 200 ||
		!strings.Contains(w.Body.String(), "Saved") {
		t.Fatalf("set credential %d %s", w.Code, w.Body.String())
	}
	if w := do("POST", "/settings/siem/splunk/credential", url.Values{"field": {"password"}, "value": {"x"}}); w.Code != 200 ||
		!strings.Contains(w.Body.String(), "does not accept") {
		t.Fatalf("bad field %s", w.Body.String())
	}
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT value FROM siem_credentials WHERE output='splunk' AND field='token'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "fake-hec-token") || !strings.HasPrefix(stored, "pi1:") {
		t.Fatalf("credential not sealed: %q", stored)
	}
	if w := do("POST", "/settings/siem/splunk/test", nil); !strings.Contains(w.Body.String(), "Test event delivered") {
		t.Fatalf("test: %s", w.Body.String())
	}
	if r, _ := c.get(0); r.Header.Get("Authorization") != "Splunk fake-hec-token" {
		t.Fatalf("auth header %q", r.Header.Get("Authorization"))
	}
	if w := do("GET", "/settings/siem", nil); strings.Contains(w.Body.String(), "fake-hec-token") {
		t.Fatal("credential rendered in page")
	}
	if w := do("GET", "/settings/siem/status", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "<table") {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	if w := do("POST", "/settings/siem/splunk/credential", url.Values{"field": {"token"}, "clear": {"1"}}); !strings.Contains(w.Body.String(), "Cleared") {
		t.Fatalf("clear %s", w.Body.String())
	}
	if w := do("POST", "/settings/siem/nope/test", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown output %d", w.Code)
	}
	want := "siem.test:failure siem.credential.set:success siem.test:success siem.credential.clear:success"
	if got := strings.Join(rec.actions(), " "); got != want {
		t.Fatalf("audit %q want %q", got, want)
	}
}
