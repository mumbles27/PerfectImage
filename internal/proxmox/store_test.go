package proxmox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

func testDB(t *testing.T) (*store.DB, secrets.Sealer) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "pi.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	sealer, err := secrets.NewAESGCM(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return db, sealer
}

func TestStoreCRUDAndSealing(t *testing.T) {
	db, sealer := testDB(t)
	ctx := context.Background()
	reg := NewRegistry(db, sealer, nil, config.ProxmoxConfig{})
	s := reg.Store()

	c, err := s.Create(ctx, ClusterInput{Name: "lab", Endpoint: "pve.example.test", TokenID: testTokenID, Secret: testSecret,
		Fingerprint: strings.Repeat("ab", 32), DefaultNode: "pve1"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "https://pve.example.test:8006/api2/json" || !c.HasSecret || !strings.HasPrefix(c.Fingerprint, "AB:AB") {
		t.Fatalf("created = %+v", c)
	}
	var raw string
	if err := db.QueryRowContext(ctx, `SELECT token_secret FROM proxmox_clusters WHERE id = ?`, c.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, testSecret) || !strings.HasPrefix(raw, "pi1:") {
		t.Fatalf("secret stored unsealed: %q", raw)
	}

	creds, err := reg.Credentials(ctx, "lab")
	if err != nil || creds.Secret != testSecret || creds.TokenID != testTokenID {
		t.Fatalf("Credentials = %v, %v", creds, err)
	}
	for _, s := range []string{creds.String(), fmt.Sprintf("%v %+v %#v", creds, creds, creds)} {
		if strings.Contains(s, testSecret) {
			t.Fatalf("Credentials formatting leaks secret: %s", s)
		}
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("x", "creds", creds)
	if strings.Contains(logBuf.String(), testSecret) {
		t.Fatal("Credentials LogValue leaks secret")
	}
	env := strings.Join(creds.PackerEnv(), "\n")
	if !strings.Contains(env, "PROXMOX_TOKEN="+testSecret) || !strings.Contains(env, "PROXMOX_USERNAME="+testTokenID) {
		t.Errorf("PackerEnv = %q", env)
	}

	// Rename without a new secret: the secret is re-sealed under the new name.
	in := inputOf(c)
	in.Name = "lab2"
	c2, err := s.Update(ctx, c.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if creds, err := reg.Credentials(ctx, "lab2"); err != nil || creds.Secret != testSecret {
		t.Fatalf("after rename: %v, %v", creds, err)
	}
	if !c2.UpdatedAt.After(c.UpdatedAt) {
		t.Error("updated_at did not advance")
	}

	if _, err := s.Create(ctx, ClusterInput{Name: "lab2", Endpoint: "https://x"}); err == nil {
		t.Error("expected duplicate-name error")
	}
	bad := []ClusterInput{
		{Name: "bad name", Endpoint: "https://x"},
		{Name: "x", Endpoint: "http://x"},
		{Name: "x", Endpoint: "https://x", TokenID: "root"},
		{Name: "x", Endpoint: "https://x", Fingerprint: "zz"},
		{Name: "x", Endpoint: "https://x", CAPEM: "not pem"},
	}
	for _, b := range bad {
		if _, err := s.Create(ctx, b); err == nil {
			t.Errorf("Create(%+v) succeeded", b)
		}
	}
	if err := s.Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Client(ctx, "lab2"); !errors.Is(err, ErrClusterNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestSeed(t *testing.T) {
	db, sealer := testDB(t)
	ctx := context.Background()
	s := NewStore(db, sealer)
	secretFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(secretFile, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ProxmoxConfig{Clusters: []config.ProxmoxCluster{
		{Name: "a", Endpoint: "https://a.example.test", TokenID: testTokenID, TokenSecretFile: secretFile},
		{Name: "b", Endpoint: "https://b.example.test"},
		{Name: "c", Endpoint: "https://c.example.test", TokenSecretFile: filepath.Join(t.TempDir(), "missing")},
	}}
	got, err := s.Seed(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), "cluster c") {
		t.Errorf("seed err = %v, want error for c", err)
	}
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("seeded = %v", got)
	}
	a, _ := s.GetByName(ctx, "a")
	if !a.HasSecret || a.Source != "config" {
		t.Errorf("a = %+v", a)
	}
	if sec, err := s.secret(a); err != nil || sec != testSecret {
		t.Errorf("secret = %q, %v", sec, err)
	}
	// Deleted clusters are not re-seeded; new names are.
	b, _ := s.GetByName(ctx, "b")
	_ = s.Delete(ctx, b.ID)
	cfg.Clusters = append(cfg.Clusters[:2], config.ProxmoxCluster{Name: "d", Endpoint: "https://d.example.test"})
	got, err = s.Seed(ctx, cfg)
	if err != nil || strings.Join(got, ",") != "d" {
		t.Fatalf("second seed = %v, %v", got, err)
	}
	if _, err := s.GetByName(ctx, "b"); !errors.Is(err, ErrClusterNotFound) {
		t.Error("deleted cluster was re-seeded")
	}
}

func TestRegistryCachesAndRefreshes(t *testing.T) {
	db, sealer := testDB(t)
	ctx := context.Background()
	f := newFakePVE(t)
	reg := NewRegistry(db, sealer, nil, config.ProxmoxConfig{})
	c, err := reg.Store().Create(ctx, ClusterInput{Name: "lab", Endpoint: f.srv.URL, TokenID: testTokenID,
		Secret: testSecret, CAPEM: string(f.caPEM())})
	if err != nil {
		t.Fatal(err)
	}
	c1, err := reg.Client(ctx, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Version(ctx); err != nil {
		t.Fatal(err)
	}
	c2, _ := reg.Client(ctx, "lab")
	if c1 != c2 {
		t.Error("client not cached")
	}
	in := inputOf(c)
	in.Secret = "99999999-9999-9999-9999-999999999999"
	if _, err := reg.Store().Update(ctx, c.ID, in); err != nil {
		t.Fatal(err)
	}
	c3, _ := reg.Client(ctx, "lab")
	if c3 == c1 {
		t.Fatal("client not rebuilt after update")
	}
	if _, err := c3.Version(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized with rotated secret", err)
	}

	noTok, _ := reg.Store().Create(ctx, ClusterInput{Name: "empty", Endpoint: "https://e.example.test"})
	if _, err := reg.ClientFor(noTok); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v", err)
	}
}

// --- web ---

type webEnv struct {
	srv    *httptest.Server
	reg    *Registry
	mu     sync.Mutex
	audits []audit.Event
}

func (e *webEnv) actions() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, a := range e.audits {
		out = append(out, a.Action+":"+string(a.Outcome))
	}
	return out
}

func newWebEnv(t *testing.T) *webEnv {
	t.Helper()
	db, sealer := testDB(t)
	e := &webEnv{reg: NewRegistry(db, sealer, nil, config.ProxmoxConfig{})}
	rec := audit.RecorderFunc(func(_ context.Context, ev audit.Event) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.audits = append(e.audits, ev)
		return nil
	})
	s := web.NewServer(web.Options{Audit: rec})
	s.SetAuthenticator(auth.DevAllowAll{})
	s.AddModule(newModule(e.reg, rec, slog.New(slog.DiscardHandler)))
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *webEnv) post(t *testing.T, path string, form url.Values, htmx bool) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", e.srv.URL)
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestSettingsPages(t *testing.T) {
	e := newWebEnv(t)
	f := newFakePVE(t)
	form := url.Values{"name": {"lab"}, "endpoint": {f.srv.URL}, "token_id": {testTokenID},
		"token_secret": {testSecret}, "fingerprint": {f.fingerprint()}, "default_node": {"pve1"}}

	// Test connection with unsaved values.
	_, body := e.post(t, "/settings/proxmox/test", form, true)
	if !strings.Contains(body, "Connected to Proxmox VE 8.3.2") || !strings.Contains(body, "pve1") {
		t.Fatalf("test body = %s", body)
	}
	resp, _ := e.post(t, "/settings/proxmox", form, false)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	c, err := e.reg.Store().GetByName(context.Background(), "lab")
	if err != nil {
		t.Fatal(err)
	}

	r, err := http.Get(e.srv.URL + "/settings/proxmox")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), "fingerprint pinned") || strings.Contains(string(b), testSecret) {
		t.Fatalf("list page = %s", b)
	}
	r, _ = http.Get(fmt.Sprintf("%s/settings/proxmox/%d", e.srv.URL, c.ID))
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if strings.Contains(string(b), testSecret) || !strings.Contains(string(b), "stored") {
		t.Fatal("edit page leaks secret or misses stored hint")
	}

	// Stored test, then a pin mismatch via the edit form (secret kept).
	_, body = e.post(t, fmt.Sprintf("/settings/proxmox/%d/test", c.ID), nil, true)
	if !strings.Contains(body, "Connected") {
		t.Fatalf("stored test = %s", body)
	}
	bad := url.Values{"id": {fmt.Sprint(c.ID)}, "name": {"lab"}, "endpoint": {f.srv.URL}, "token_id": {testTokenID},
		"fingerprint": {strings.Repeat("00", 32)}}
	_, body = e.post(t, "/settings/proxmox/test", bad, true)
	if !strings.Contains(body, "does not match") || !strings.Contains(body, f.fingerprint()) {
		t.Fatalf("mismatch body = %s", body)
	}

	// Invalid update re-renders with an error, keeping the secret out.
	resp, body = e.post(t, fmt.Sprintf("/settings/proxmox/%d", c.ID), url.Values{"name": {"lab"}, "endpoint": {"http://x"}, "token_secret": {testSecret}}, false)
	if resp.StatusCode != http.StatusUnprocessableEntity || strings.Contains(body, testSecret) {
		t.Fatalf("bad update = %d", resp.StatusCode)
	}
	resp, _ = e.post(t, fmt.Sprintf("/settings/proxmox/%d/delete", c.ID), nil, false)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
	want := []string{"proxmox.cluster.test:success", "proxmox.cluster.create:success", "proxmox.cluster.test:success",
		"proxmox.cluster.test:failure", "proxmox.cluster.update:failure", "proxmox.cluster.delete:success"}
	if got := e.actions(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audits = %v", got)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, a := range e.audits {
		if strings.Contains(fmt.Sprintf("%+v", a), testSecret) {
			t.Fatal("audit event leaks secret")
		}
	}
}
