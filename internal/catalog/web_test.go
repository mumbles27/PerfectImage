package catalog

import (
	"bytes"
	"context"
	"io"
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
	"github.com/mumbles27/PerfectImage/internal/cli"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// roleAuth authenticates as the built-in role named in X-Test-Role.
type roleAuth struct{}

func (roleAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	role := r.Header.Get("X-Test-Role")
	if role == "" {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Principal{ID: role, Username: strings.ToLower(role), Roles: []string{role},
		Permissions: rbac.RolePermissions(role)}, nil
}

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		out = append(out, e.Action+":"+string(e.Outcome))
	}
	return out
}

func newWebEnv(t *testing.T) (*httptest.Server, *Store, *recorder, string) {
	t.Helper()
	dir := t.TempDir()
	st := NewStore(EmbeddedFS(), []string{dir}, nil)
	if _, err := st.Reload(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	srv := web.NewServer(web.Options{Audit: rec, Version: "test"})
	srv.SetAuthenticator(roleAuth{})
	srv.AddModule(NewModule(st, srv, rec))
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, st, rec, dir
}

func do(t *testing.T, ts *httptest.Server, method, path, role string, form url.Values, hdr ...string) (int, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, ts.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if role != "" {
		req.Header.Set("X-Test-Role", role)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestCatalogPages(t *testing.T) {
	ts, _, _, _ := newWebEnv(t)
	tests := []struct {
		name, method, path, role string
		want                     int
		contains                 string
	}{
		{"anonymous", "GET", "/catalog", "", http.StatusUnauthorized, ""},
		{"viewer browse apps", "GET", "/catalog", rbac.RoleViewer, 200, "Visual Studio Code"},
		{"search", "GET", "/catalog?tab=apps&q=7-zip", rbac.RoleViewer, 200, "7-Zip"},
		{"images tab", "GET", "/catalog?tab=images", rbac.RoleViewer, 200, "Windows 11"},
		{"bundles tab", "GET", "/catalog?tab=bundles", rbac.RoleViewer, 200, "developer-base"},
		{"app detail", "GET", "/catalog/apps/git", rbac.RoleViewer, 200, "winget"},
		{"image detail", "GET", "/catalog/images/ubuntu-24.04", rbac.RoleViewer, 200, "image.yaml"},
		{"bundle detail", "GET", "/catalog/bundles/sysadmin", rbac.RoleViewer, 200, "PuTTY"},
		{"missing app", "GET", "/catalog/apps/nope", rbac.RoleViewer, 404, ""},
		{"viewer cannot edit", "GET", "/catalog/apps/git/edit", rbac.RoleViewer, 403, ""},
		{"builder edits", "GET", "/catalog/apps/git/edit", rbac.RoleBuilder, 200, "<textarea"},
		{"clone renames", "GET", "/catalog/apps/git/clone", rbac.RoleBuilder, 200, "id: git-copy"},
		{"htmx results partial", "GET", "/catalog?tab=apps&q=git", rbac.RoleViewer, 200, "Git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := do(t, ts, tt.method, tt.path, tt.role, nil)
			if code != tt.want {
				t.Fatalf("status = %d, want %d", code, tt.want)
			}
			if tt.contains != "" && !strings.Contains(body, tt.contains) {
				t.Fatalf("body does not contain %q", tt.contains)
			}
		})
	}
	code, body := do(t, ts, "GET", "/catalog?tab=apps&q=git", rbac.RoleViewer, nil, "HX-Request", "true", "HX-Target", "catalog-results")
	if code != 200 || strings.Contains(body, "<html") {
		t.Fatalf("partial: %d html=%v", code, strings.Contains(body, "<html"))
	}
}

func TestCatalogEditorSaveAudits(t *testing.T) {
	ts, st, rec, dir := newWebEnv(t)
	bundle := "id: mine\nname: Mine\napps: [git, jq]\n"

	// Validate only: nothing is written.
	code, body := do(t, ts, "POST", "/catalog/bundles", rbac.RoleBuilder,
		url.Values{"yaml": {bundle}, "mode": {ModeCreate}, "action": {"validate"}}, "HX-Request", "true")
	if code != 200 || !strings.Contains(body, "Definition is valid") {
		t.Fatalf("validate: %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(dir, "bundles", "mine.yaml")); !os.IsNotExist(err) {
		t.Fatal("validate wrote a file")
	}

	// Invalid save is rejected with problems and audited as a failure.
	code, body = do(t, ts, "POST", "/catalog/bundles", rbac.RoleBuilder,
		url.Values{"yaml": {"id: mine\nname: Mine\napps: [ghost]\n"}, "mode": {ModeCreate}, "action": {"save"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "unknown app") {
		t.Fatalf("invalid save: %d", code)
	}

	// Viewer cannot save.
	if code, _ := do(t, ts, "POST", "/catalog/bundles", rbac.RoleViewer, url.Values{"yaml": {bundle}, "mode": {ModeCreate}}); code != 403 {
		t.Fatalf("viewer save: %d", code)
	}

	code, _ = do(t, ts, "POST", "/catalog/bundles", rbac.RoleBuilder,
		url.Values{"yaml": {bundle}, "mode": {ModeCreate}, "action": {"save"}})
	if code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	b, err := os.ReadFile(filepath.Join(dir, "bundles", "mine.yaml"))
	if err != nil || string(b) != bundle {
		t.Fatalf("saved file = %q, %v", b, err)
	}
	if st.Catalog().Bundles["mine"] == nil {
		t.Fatal("catalog not reloaded after save")
	}
	if code, _ := do(t, ts, "POST", "/catalog/bundles/mine/revert", rbac.RoleBuilder, url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("revert: %d", code)
	}
	got := strings.Join(rec.actions(), ",")
	for _, want := range []string{"catalog.bundle.create:failure", "catalog.bundle.create:success", "catalog.bundle.delete:success"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit %q missing from %s", want, got)
		}
	}
}

func TestValidateCLI(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "apps"), 0o700); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		file     string
		wantCode int
		wantOut  string
	}{
		{"ok", "id: tool\nname: Tool\ncategory: utility\ninstall:\n  linux:\n    - apt: {packages: [tool]}\n      verify: command -v tool\n", 0, "catalog OK"},
		{"problem", "id: tool\nname: Tool\ncategory: nope\n", 1, "tool.yaml:3: category"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "apps", "tool.yaml"), []byte(tt.file), 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := cli.Main(context.Background(), &cli.Env{Stdout: &out, Stderr: &errOut},
				[]string{"catalog", "validate", "--dir", dir})
			if code != tt.wantCode || !strings.Contains(out.String(), tt.wantOut) {
				t.Fatalf("code %d out %q err %q", code, out.String(), errOut.String())
			}
		})
	}
}
