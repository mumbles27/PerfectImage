package packer

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

type roleAuth struct{}

func (roleAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	role := r.Header.Get("X-Test-Role")
	if role == "" {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Principal{ID: role, Username: strings.ToLower(role), Roles: []string{role},
		Permissions: rbac.RolePermissions(role)}, nil
}

func TestBuildPages(t *testing.T) {
	e := newJobEnv(t, "ok", "never")
	srv := web.NewServer(web.Options{Jobs: e.mgr, Version: "test"})
	srv.SetAuthenticator(roleAuth{})
	srv.AddModule(NewModule(e.svc, srv, func() []string { return []string{"lab"} }))
	// The wizard links to the catalog stylesheet; the catalog module serves it.
	srv.AddModule(catalog.NewModule(e.svc.cat, srv, nil))
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path, role string, form url.Values) (int, string, string) {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequest(method, ts.URL+path, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Header.Set("X-Test-Role", role)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header.Get("Location")
	}
	valid := url.Values{"image": {"ubuntu-24.04"}, "cluster": {"lab"}, "node": {"pve1"},
		"template_name": {"ubuntu-web"}, "apps": {"git"}, "bundles": {"browsers"}}
	invalid := url.Values{"image": {"ubuntu-24.04"}, "cluster": {"lab"}, "node": {"pve1"}, "template_name": {"bad name"}}

	tests := []struct {
		name, method, path, role string
		form                     url.Values
		want                     int
		contains, location       string
	}{
		{"viewer sees history only", "GET", "/build", rbac.RoleViewer, nil, 200, "Build history", ""},
		{"builder sees wizard", "GET", "/build?image=windows-11", rbac.RoleBuilder, nil, 200, "virtio-win ISO", ""},
		{"viewer cannot build", "POST", "/build", rbac.RoleViewer, valid, 403, "", ""},
		{"invalid request", "POST", "/build", rbac.RoleBuilder, invalid, 422, "Letters, digits", ""},
		{"submit", "POST", "/build", rbac.RoleBuilder, valid, 303, "", "/jobs/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body, loc := do(tt.method, tt.path, tt.role, tt.form)
			if code != tt.want {
				t.Fatalf("status %d, want %d", code, tt.want)
			}
			if !strings.Contains(body, tt.contains) || !strings.HasPrefix(loc, tt.location) {
				t.Fatalf("body/location mismatch: %q", loc)
			}
			if tt.name == "viewer sees history only" && strings.Contains(body, "Start build") {
				t.Fatal("viewer sees the wizard")
			}
		})
	}
	builds, err := e.svc.Builds(t.Context(), 10)
	if err != nil || len(builds) != 1 || builds[0].TemplateName != "ubuntu-web" {
		t.Fatalf("builds = %v, %v", builds, err)
	}
	if code, body, _ := do("GET", "/build/"+builds[0].ID, rbac.RoleViewer, nil); code != 200 || !strings.Contains(body, "ubuntu-web") {
		t.Fatalf("detail %d", code)
	}
}
