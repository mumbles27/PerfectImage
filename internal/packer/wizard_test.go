package packer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// fakeInventory is a two-cluster lab with per-node storages and bridges.
type fakeInventory struct{ fakeCreds }

func (fakeInventory) Clusters(context.Context) ([]string, error) { return []string{"lab", "prod"}, nil }

func (fakeInventory) Nodes(_ context.Context, cluster string) ([]string, error) {
	switch cluster {
	case "lab":
		return []string{"pve1", "pve2"}, nil
	case "prod":
		return nil, errors.New("connection refused")
	}
	return nil, errors.New("unknown cluster")
}

func (fakeInventory) Storages(_ context.Context, _, node string) ([]string, error) {
	return []string{"local-zfs", "ceph-" + node}, nil
}

func (fakeInventory) Bridges(_ context.Context, _, node string) ([]string, error) {
	return []string{"vmbr0", "vmbr9-" + node}, nil
}

func (fakeInventory) ISOStorages(context.Context, string, string) ([]string, error) {
	return []string{"local", "nas"}, nil
}

func (fakeInventory) ISOs(_ context.Context, _, _, storage string) ([]string, error) {
	return []string{storage + ":iso/install-" + storage + ".iso"}, nil
}

func (fakeInventory) Defaults(context.Context, string) (TargetDefaults, error) {
	return TargetDefaults{Node: "pve2", Storage: "local-zfs", Bridge: "vmbr0"}, nil
}

// blindInventory reaches the cluster but sees nothing on the node, like a
// privilege-separated token without ACLs.
type blindInventory struct{ fakeInventory }

func (blindInventory) Storages(context.Context, string, string) ([]string, error)    { return nil, nil }
func (blindInventory) Bridges(context.Context, string, string) ([]string, error)     { return nil, nil }
func (blindInventory) ISOStorages(context.Context, string, string) ([]string, error) { return nil, nil }

func TestWizardTokenWithoutPermissions(t *testing.T) {
	_, ts := newWebEnv(t, blindInventory{})
	code, body := get(t, ts, "/build", rbac.RoleBuilder)
	if code != 200 || !strings.Contains(body, "can see no storages, bridges or ISOs on pve2") ||
		!strings.Contains(body, `<input name="storage"`) {
		t.Fatalf("permission hint missing (%d)", code)
	}
	_, ok := newWebEnv(t, fakeInventory{})
	if _, body := get(t, ok, "/build", rbac.RoleBuilder); strings.Contains(body, "can see no storages") {
		t.Fatal("hint shown for a token that sees resources")
	}
}

// newWebEnv is a build service whose jobs are queued but never run, so the
// wizard can be tested on every OS (no fake packer needed).
func newWebEnv(t *testing.T, creds ClusterCreds) (*Service, *httptest.Server) {
	t.Helper()
	ctx := context.Background()
	tmp := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(tmp, "pi.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	key, _ := secrets.NewKey()
	sealer, _ := secrets.NewAESGCM(key)
	cat := catalog.NewStore(catalog.EmbeddedFS(), nil, nil)
	if _, err := cat.Reload(ctx, true); err != nil {
		t.Fatal(err)
	}
	mgr := jobs.New(db, jobs.Options{Workers: 1})
	svc := NewService(Options{Config: config.PackerConfig{WorkDir: filepath.Join(tmp, "work")}, Catalog: cat, DB: db,
		Sealer: sealer, Jobs: mgr, Creds: creds, Seeds: &fakeSeeds{}})
	if err := mgr.Register(JobType, svc); err != nil {
		t.Fatal(err)
	}
	srv := web.NewServer(web.Options{Jobs: mgr, Version: "test"})
	srv.SetAuthenticator(roleAuth{})
	srv.AddModule(NewModule(svc, srv, nil))
	srv.AddModule(catalog.NewModule(cat, srv, nil))
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return svc, ts
}

func post(t *testing.T, ts *httptest.Server, path, role string, form url.Values) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test-Role", role)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func get(t *testing.T, ts *httptest.Server, path, role string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Header.Set("X-Test-Role", role)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestWizardInventoryAndRefresh(t *testing.T) {
	svc, ts := newWebEnv(t, fakeInventory{})

	code, body := get(t, ts, "/build", rbac.RoleBuilder)
	if code != 200 {
		t.Fatalf("GET /build = %d", code)
	}
	for _, want := range []string{
		`<option value="pve2" selected>`,           // cluster default node preselected
		`<option value="ceph-pve2">`,               // storages of that node
		`<option value="vmbr9-pve2">`,              // bridges of that node
		`<option value="nas:iso/install-nas.iso">`, // ISOs from every ISO storage
		`<option value="local-zfs" selected>`,      // image default local-lvm missing -> cluster default
		`hx-post="/build/form"`, "4. OS settings", "6. Post-install script",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("wizard lacks %q", want)
		}
	}

	// Switching the node reloads its storages and keeps typed values.
	code, body = post(t, ts, "/build/form", rbac.RoleBuilder, url.Values{"image": {"ubuntu-24.04"}, "cluster": {"lab"},
		"node": {"pve1"}, "timezone": {"Europe/Berlin"}, "post_script": {"echo kept"}, "template_name": {"my-name"}})
	if code != 200 || !strings.Contains(body, `<option value="ceph-pve1">`) || strings.Contains(body, "ceph-pve2") ||
		!strings.Contains(body, `value="Europe/Berlin"`) || !strings.Contains(body, "echo kept") || !strings.Contains(body, `value="my-name"`) {
		t.Fatalf("refresh after node change (%d) lost state", code)
	}

	// Switching the image regenerates an auto-generated template name and
	// offers the Windows options.
	_, first := get(t, ts, "/build?image=ubuntu-24.04", rbac.RoleBuilder)
	auto := DefaultTemplateName("ubuntu-24.04", time.Now())
	if !strings.Contains(first, `name="auto_name" value="`+auto+`"`) {
		t.Fatalf("auto name %q not rendered", auto)
	}
	_, body = post(t, ts, "/build/form", rbac.RoleBuilder, url.Values{"image": {"windows-server-2025"}, "cluster": {"lab"},
		"node": {"pve1"}, "template_name": {auto}, "auto_name": {auto}})
	for _, want := range []string{DefaultTemplateName("windows-server-2025", time.Now()), "SERVERDATACENTERCORE",
		"virtio-win ISO", "PowerShell script", "Windows Update"} {
		if !strings.Contains(body, want) {
			t.Fatalf("windows wizard lacks %q", want)
		}
	}

	// An unreachable cluster degrades to free-text fields with a notice.
	_, body = post(t, ts, "/build/form", rbac.RoleBuilder, url.Values{"image": {"ubuntu-24.04"}, "cluster": {"prod"}})
	if !strings.Contains(body, "Could not reach cluster prod") || !strings.Contains(body, `<input name="node"`) {
		t.Fatal("unreachable cluster not reported")
	}

	// Viewers cannot use the refresh endpoint.
	if code, _ := post(t, ts, "/build/form", rbac.RoleViewer, url.Values{"image": {"ubuntu-24.04"}}); code != 403 {
		t.Fatalf("viewer refresh = %d", code)
	}

	// Invalid options are reported on their fields.
	code, body = post(t, ts, "/build", rbac.RoleBuilder, url.Values{"image": {"ubuntu-24.04"}, "cluster": {"lab"}, "node": {"pve1"},
		"template_name": {"t1"}, "timezone": {"Pacific Standard Time"}, "post_script_reboot": {"1"}})
	if code != 422 || !strings.Contains(body, "IANA time zone") || !strings.Contains(body, "untick the reboot") {
		t.Fatalf("invalid options: %d", code)
	}

	// A valid submit stores settings and the script with the build.
	code, _ = post(t, ts, "/build", rbac.RoleBuilder, url.Values{"image": {"windows-server-2025"}, "cluster": {"lab"}, "node": {"pve1"},
		"template_name": {"ws-opts"}, "timezone": {"UTC"}, "os_updates": {"1"}, "windows_edition": {"Windows Server 2025 SERVERDATACENTER"},
		"post_script": {"Write-Host hi\r\n"}, "post_script_reboot": {"1"}})
	if code != 303 {
		t.Fatalf("submit = %d", code)
	}
	builds, err := svc.Builds(t.Context(), 5)
	if err != nil || len(builds) != 1 {
		t.Fatalf("builds %v %v", builds, err)
	}
	b, err := svc.Build(t.Context(), builds[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	r := b.Request
	if r.Settings != (OSSettings{Timezone: "UTC", Updates: true, WindowsEdition: "Windows Server 2025 SERVERDATACENTER"}) ||
		r.PostScript != (PostScript{Script: "Write-Host hi\n", Reboot: true}) {
		t.Fatalf("stored request %+v", r)
	}
	if strings.Join(b.Apps, ",") != "7zip" {
		t.Fatalf("apps %v must not include generated steps", b.Apps)
	}
	if code, body := get(t, ts, "/build/"+b.ID, rbac.RoleViewer); code != 200 || !strings.Contains(body, "Write-Host hi") ||
		!strings.Contains(body, "Windows Update") {
		t.Fatalf("detail page (%d) lacks options", code)
	}
}
