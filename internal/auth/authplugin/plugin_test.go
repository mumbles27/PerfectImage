package authplugin

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
	"github.com/mumbles27/PerfectImage/internal/web"
)

func TestParseRoleMap(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string][]string
		ok   bool
	}{
		{"empty", "", map[string][]string{}, true},
		{"simple", "admins => Admin\n# comment\n\nops => Operator, Viewer", map[string][]string{"admins": {"Admin"}, "ops": {"Operator", "Viewer"}}, true},
		{"dn with = and ,", "CN=PI Admins,OU=Groups,DC=example,DC=com => Admin", map[string][]string{"CN=PI Admins,OU=Groups,DC=example,DC=com": {"Admin"}}, true},
		{"missing arrow", "admins Admin", nil, false},
		{"missing roles", "admins =>  ", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRoleMap(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v", err)
			}
			if tt.ok && formatRoleMap(got) != formatRoleMap(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRedirectKeepsFragment(t *testing.T) {
	w := httptest.NewRecorder()
	redirect(w, httptest.NewRequest("POST", "/", nil), "/settings/sso#ldap", "saved")
	if got := w.Header().Get("Location"); got != "/settings/sso?msg=saved#ldap" {
		t.Fatalf("Location = %q", got)
	}
}

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	svc    *auth.Service
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	key, _ := secrets.NewKey()
	sealer, _ := secrets.NewAESGCM(key)
	svc := auth.NewService(auth.Options{
		DB: db, Sealer: sealer, Config: config.AuthConfig{LoginRatePerIP: -1, LoginRatePerUser: -1},
		Argon2: &auth.Argon2Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32},
	})
	if err := svc.Init(ctx); err != nil {
		t.Fatal(err)
	}
	ws := web.NewServer(web.Options{Version: "test"})
	ws.SetCSRF(svc.CSRF())
	ws.SetAuthenticator(svc)
	ws.SetAuthorizer(svc)
	ws.AddModule(&module{svc: svc, srv: ws})
	h, err := ws.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &harness{t: t, srv: srv, svc: svc, client: &http.Client{
		Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func (h *harness) get(path string) (int, string, string) {
	h.t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(b)
}

func (h *harness) post(path, csrfFrom string, form url.Values) (int, string, string) {
	h.t.Helper()
	_, _, page := h.get(csrfFrom)
	m := csrfRE.FindStringSubmatch(page)
	if m == nil {
		h.t.Fatalf("no csrf token on %s", csrfFrom)
	}
	form.Set("csrf_token", m[1])
	resp, err := h.client.PostForm(h.srv.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), string(b)
}

func TestEndToEndSignIn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pw, err := h.svc.ResetAdmin(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}

	steps := []struct {
		name         string
		do           func() (int, string, string)
		wantStatus   int
		wantLocation string
		wantBody     string
	}{
		{"protected page redirects", func() (int, string, string) { return h.get("/settings/users") }, 303, "/login?next=%2Fsettings%2Fusers", ""},
		{"login page", func() (int, string, string) { return h.get("/login") }, 200, "", "Sign in"},
		{"post without csrf", func() (int, string, string) {
			resp, _ := h.client.PostForm(h.srv.URL+"/login", url.Values{"username": {"admin"}, "password": {pw}})
			resp.Body.Close()
			return resp.StatusCode, "", ""
		}, 403, "", ""},
		{"bad password", func() (int, string, string) {
			return h.post("/login", "/login", url.Values{"username": {"admin"}, "password": {"wrong"}})
		}, 401, "", "Invalid username or password"},
		{"good password -> forced change", func() (int, string, string) {
			return h.post("/login", "/login", url.Values{"username": {"admin"}, "password": {pw}, "next": {"/settings/users"}})
		}, 303, "/login/password?next=%2Fsettings%2Fusers", ""},
		{"pending session is not signed in", func() (int, string, string) { return h.get("/account") }, 303, "/login?next=%2Faccount", ""},
		{"weak new password", func() (int, string, string) {
			return h.post("/login/password", "/login/password", url.Values{"current_password": {pw}, "new_password": {"password1234"}, "confirm_password": {"password1234"}})
		}, 400, "", "too common"},
		{"change password", func() (int, string, string) {
			return h.post("/login/password", "/login/password", url.Values{"current_password": {pw}, "new_password": {"Lantern-Purple-42"},
				"confirm_password": {"Lantern-Purple-42"}, "next": {"/settings/users"}})
		}, 303, "/settings/users", ""},
		{"users page", func() (int, string, string) { return h.get("/settings/users") }, 200, "", "Create local user"},
		{"roles page", func() (int, string, string) { return h.get("/settings/roles") }, 200, "", "images.build"},
		{"sso page", func() (int, string, string) { return h.get("/settings/sso") }, 200, "", "LDAP / Active Directory"},
		{"account page", func() (int, string, string) { return h.get("/account") }, 200, "", "API tokens"},
		{"create user", func() (int, string, string) {
			return h.post("/settings/users", "/settings/users", url.Values{"username": {"zoe"}, "roles": {"Viewer"}})
		}, 200, "", "One-time password for"},
		{"create custom role", func() (int, string, string) {
			return h.post("/settings/roles", "/settings/roles", url.Values{"name": {"Auditors"}, "permissions": {"audit.view"}})
		}, 303, "/settings/roles/Auditors?msg=created", ""},
		{"delete builtin role refused", func() (int, string, string) {
			return h.post("/settings/roles/Admin/delete", "/settings/roles", url.Values{})
		}, 400, "", "Built-in roles"},
		{"start mfa", func() (int, string, string) { return h.post("/account/mfa/begin", "/account", url.Values{}) }, 303, "/account#mfa", ""},
		{"qr shown", func() (int, string, string) { return h.get("/account") }, 200, "", `src="data:image/png;base64,`},
		{"create token", func() (int, string, string) {
			return h.post("/account/tokens", "/account", url.Values{"name": {"ci"}, "days": {"7"}, "permissions": {"jobs.view"}})
		}, 200, "", auth.TokenPrefix},
		{"logout", func() (int, string, string) { return h.post("/logout", "/account", url.Values{}) }, 303, "/login", ""},
		{"signed out", func() (int, string, string) { return h.get("/account") }, 303, "/login?next=%2Faccount", ""},
	}
	for _, st := range steps {
		status, loc, body := st.do()
		if status != st.wantStatus || (st.wantLocation != "" && loc != st.wantLocation) || !strings.Contains(body, st.wantBody) {
			t.Fatalf("%s: status=%d location=%q (want %d %q, body containing %q)\n%.400s", st.name, status, loc,
				st.wantStatus, st.wantLocation, st.wantBody, body)
		}
	}
	users, _ := h.svc.Users(ctx)
	if len(users) != 2 || users[1].Username != "zoe" || !slices.Equal(users[1].Roles, []string{"Viewer"}) {
		t.Fatalf("users = %+v", users)
	}
}

func TestResetAdminCLI(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := writeFile(cfgPath, "data_dir: ./data\nlog:\n  stdout: false\n"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	pw1, err := resetAdmin(context.Background(), cfg, "admin")
	if err != nil || len(pw1) < 20 {
		t.Fatalf("first reset: %q, %v", pw1, err)
	}
	pw2, err := resetAdmin(context.Background(), cfg, "admin")
	if err != nil || pw2 == pw1 {
		t.Fatalf("second reset: %v", err)
	}
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
