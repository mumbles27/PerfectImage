package deploy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/store"
	"github.com/mumbles27/PerfectImage/internal/web"
)

type fakeEnqueuer struct {
	mu       sync.Mutex
	payloads []json.RawMessage
}

func (e *fakeEnqueuer) Enqueue(_ context.Context, typ string, payload any, _ string) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.payloads = append(e.payloads, b)
	return "job-" + typ, nil
}

// roleAuth authenticates as the built-in role named in X-Role (default Admin).
type roleAuth struct{}

func (roleAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	role := r.Header.Get("X-Role")
	if role == "" {
		role = rbac.RoleAdmin
	}
	return &auth.Principal{ID: role, Username: strings.ToLower(role), Roles: []string{role},
		Permissions: rbac.RolePermissions(role)}, nil
}

type webEnv struct {
	srv   *httptest.Server
	f     *fakePVE
	enq   *fakeEnqueuer
	hist  *HistoryStore
	audit *recAudit
}

func newWebEnv(t *testing.T) *webEnv {
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
	SetAppResolver(testResolver)
	t.Cleanup(func() { SetAppResolver(nil) })
	e := &webEnv{f: newFakePVE(), enq: &fakeEnqueuer{}, hist: NewHistoryStore(db), audit: &recAudit{}}
	s := web.NewServer(web.Options{Audit: e.audit})
	s.SetAuthenticator(roleAuth{})
	s.AddModule(&module{clients: newFakeSource(e.f), sealer: testSealer(t), jobs: e.enq, history: e.hist,
		audit: e.audit, log: slog.New(slog.DiscardHandler)})
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *webEnv) do(t *testing.T, method, path, role string, form url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Origin", e.srv.URL)
	if role != "" {
		req.Header.Set("X-Role", role)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestWizardPages(t *testing.T) {
	e := newWebEnv(t)
	tests := []struct {
		name, path, role string
		status           int
		want             []string
	}{
		{"wizard preselects single cluster", "/deploy", "", 200, []string{"Deploy a VM", "ubuntu-24.04 (9000 on pve1)", "★", "vmbr1", "perfectimage"}},
		{"viewer redirected to templates", "/deploy", rbac.RoleViewer, 303, nil},
		{"options partial", "/deploy/options?cluster=lab", "", 200, []string{`name="template"`, "win2022", `hx-swap-oob="true"`}},
		{"options for node keeps os", "/deploy/options?cluster=lab&template=pve1/9000&node=pve2", "", 200, []string{`value="pve2" selected`}},
		{"linux os fields", "/deploy/osfields?cluster=lab&template=pve1/9000", "", 200, []string{"cloud-init", "ssh_keys", "NGINX"}},
		{"windows os fields", "/deploy/osfields?cluster=lab&template=pve1/9001", "", 200, []string{"admin_password", "Domain join", "7-Zip"}},
		{"non-template rejected", "/deploy/osfields?cluster=lab&template=pve1/500", "", 200, []string{"not a template"}},
		{"viewer cannot load options", "/deploy/options?cluster=lab", rbac.RoleViewer, 403, nil},
		{"templates page", "/deploy/templates", rbac.RoleViewer, 200, []string{"PerfectImage", "build_id:", "b-123", "win2022"}},
		{"history page", "/deploy/history", rbac.RoleViewer, 200, []string{"No deployments yet"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do(t, http.MethodGet, tt.path, tt.role, nil)
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d\n%s", resp.StatusCode, tt.status, body)
			}
			for _, w := range tt.want {
				if !strings.Contains(body, w) {
					t.Errorf("body missing %q", w)
				}
			}
		})
	}
	// Viewers see no delete buttons.
	_, body := e.do(t, http.MethodGet, "/deploy/templates", rbac.RoleViewer, nil)
	if strings.Contains(body, "/deploy/templates/delete") {
		t.Error("viewer sees delete button")
	}
	_, body = e.do(t, http.MethodGet, "/deploy/templates", rbac.RoleOperator, nil)
	if !strings.Contains(body, "/deploy/templates/delete") {
		t.Error("operator misses delete button")
	}
}

func TestWizardSubmit(t *testing.T) {
	e := newWebEnv(t)
	form := url.Values{
		"cluster": {"lab"}, "template": {"pve1/9001"}, "node": {"pve1"}, "storage": {"local-lvm"}, "pool": {"perfectimage"},
		"name": {"win01"}, "cores": {"2"}, "memory_mb": {"4096"}, "disk_gb": {"60"}, "bridge": {"vmbr0"}, "vlan": {"20"},
		"ip_mode": {"dhcp"}, "hostname": {"WIN01"}, "admin_password": {fakeAdminPW}, "admin_password_confirm": {fakeAdminPW},
		"apps": {"7zip"}, "cleanup": {"1"},
	}
	resp, body := e.do(t, http.MethodPost, "/deploy", rbac.RoleOperator, form)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/jobs/job-deploy.vm" {
		t.Fatalf("submit = %d %s\n%s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	if len(e.enq.payloads) != 1 {
		t.Fatal("not enqueued")
	}
	raw := string(e.enq.payloads[0])
	if strings.Contains(raw, fakeAdminPW) {
		t.Fatal("plaintext password in job payload")
	}
	var req Request
	_ = json.Unmarshal(e.enq.payloads[0], &req)
	if req.OS != OSWindows || req.TemplateName != "win2022" || req.VLAN != 20 || !req.CleanupOnFailure || req.Windows.Hostname != "WIN01" {
		t.Errorf("request = %+v", req)
	}
	pw, err := OpenSecret(testSealer(t), req.RequestID, "admin_password", req.Windows.AdminPassword)
	if err != nil || pw != fakeAdminPW {
		t.Fatalf("unseal = %q, %v", pw, err)
	}
	list, _ := e.hist.List(context.Background(), 10)
	if len(list) != 1 || list[0].Status != StatusQueued || list[0].RequestedBy != "operator" {
		t.Errorf("history = %+v", list)
	}

	// Validation errors re-render the form without the password.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("admin_password_confirm", "different")
	bad.Set("name", "bad name")
	resp, body = e.do(t, http.MethodPost, "/deploy", rbac.RoleOperator, bad)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "do not match") ||
		!strings.Contains(body, "valid DNS name") || strings.Contains(body, fakeAdminPW) {
		t.Fatalf("bad submit = %d\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `value="WIN01"`) {
		t.Error("form values not preserved")
	}
	if resp, _ := e.do(t, http.MethodPost, "/deploy", rbac.RoleViewer, form); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer submit = %d", resp.StatusCode)
	}
	var got []string
	for _, a := range e.audit.events {
		got = append(got, a.Action+":"+string(a.Outcome))
	}
	if strings.Join(got, ",") != "deploy.vm.request:success,deploy.vm.request:failure,authz.deny:denied" {
		t.Errorf("audits = %v", got)
	}
}

func TestDeleteTemplate(t *testing.T) {
	e := newWebEnv(t)
	// Builder has images.build but not deploy.view; delete is still allowed.
	resp, _ := e.do(t, http.MethodPost, "/deploy/templates/delete", rbac.RoleBuilder,
		url.Values{"cluster": {"lab"}, "node": {"pve1"}, "vmid": {"500"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Fatalf("non-template delete = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.f.has("DeleteVM") {
		t.Fatal("deleted a non-template VM")
	}
	if resp, _ := e.do(t, http.MethodPost, "/deploy/templates/delete", rbac.RoleViewer,
		url.Values{"cluster": {"lab"}, "node": {"pve1"}, "vmid": {"9000"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer delete = %d", resp.StatusCode)
	}
	resp, _ = e.do(t, http.MethodPost, "/deploy/templates/delete", rbac.RoleOperator,
		url.Values{"cluster": {"lab"}, "node": {"pve1"}, "vmid": {"9000"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "notice=") || !e.f.has("DeleteVM 9000") {
		t.Fatalf("delete = %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var got []string
	for _, a := range e.audit.events {
		got = append(got, a.Action+":"+string(a.Outcome))
	}
	if strings.Join(got, ",") != "image.template.delete:failure,authz.deny:denied,image.template.delete:success" {
		t.Errorf("audits = %v", got)
	}
}
