package packer

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

const (
	fakeToken = "fake-token-secret-0000"
	fakeUser  = "fake@pve!perfectimage"
)

// fakePacker emulates packer. Its behaviour is chosen by the file "mode"
// beside it (the runner does not pass arbitrary env vars through); it
// appends its argv to "args" and its PROXMOX_* env names to "env".
const fakePacker = `#!/bin/sh
here=$(dirname "$0")
mode=$(cat "$here/mode" 2>/dev/null)
echo "$*" >> "$here/args"
env | grep -E '^(PROXMOX_|PKR_VAR_)' | cut -d= -f1 | sort | tr '\n' ' ' > "$here/env"; echo >> "$here/env"
case "$1" in
init|validate)
  [ -f perfectimage.auto.pkrvars.hcl ] || { echo "no vars file" >&2; exit 3; }
  echo "$1 ok"; exit 0 ;;
build)
  echo "1700000000,,ui,say,==> proxmox-iso.image: Creating VM"
  echo "1700000000,proxmox-iso.image,ui,message,    leaked token=$PROXMOX_TOKEN password=$PKR_VAR_build_password"
  echo "warning on stderr" >&2
  case "$mode" in
  hang)
    trap 'echo "1700000001,,ui,say,interrupted%!(PACKER_COMMA) deleting VM"; exit 1' INT
    while :; do sleep 0.05; done ;;
  fail)
    echo "1700000001,,ui,error,Build 'proxmox-iso.image' errored"; exit 1 ;;
  esac
  echo "1700000002,proxmox-iso.image,artifact,0,id,9001"
  echo "1700000002,proxmox-iso.image,artifact,0,string,A template was created: 9001"
  exit 0 ;;
esac
exit 2
`

type fakeCreds struct{}

func (fakeCreds) Creds(_ context.Context, cluster string) (string, string, string, bool, error) {
	if cluster != "lab" {
		return "", "", "", false, errors.New("unknown cluster")
	}
	return "https://pve.example.invalid:8006", fakeUser, fakeToken, true, nil
}

type jobEnv struct {
	svc  *Service
	mgr  *jobs.Manager
	bin  string
	work string
}

func newJobEnv(t *testing.T, mode string, keep string) *jobEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake packer is a shell script")
	}
	ctx := context.Background()
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "fake")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "packer")
	if err := os.WriteFile(bin, []byte(fakePacker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "mode"), []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(tmp, "pi.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	key, _ := secrets.NewKey()
	sealer, err := secrets.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.NewStore(catalog.EmbeddedFS(), nil, nil)
	if _, err := cat.Reload(ctx, true); err != nil {
		t.Fatal(err)
	}
	mgr := jobs.New(db, jobs.Options{Workers: 1, PollInterval: 10 * time.Millisecond})
	cfg := config.PackerConfig{Binary: bin, WorkDir: filepath.Join(tmp, "work"), KeepWorkDir: keep,
		InterruptGrace: 3 * time.Second, BuildTimeout: time.Minute}
	svc := NewService(Options{Config: cfg, Catalog: cat, DB: db, Sealer: sealer, Jobs: mgr, Creds: fakeCreds{}})
	if err := mgr.Register(JobType, svc); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = mgr.Stop(c)
	})
	return &jobEnv{svc: svc, mgr: mgr, bin: binDir, work: cfg.WorkDir}
}

func (e *jobEnv) wait(t *testing.T, id string) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		j, err := e.mgr.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status.Terminal() {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func (e *jobEnv) logs(t *testing.T, id string) string {
	t.Helper()
	lines, err := e.mgr.Logs(context.Background(), id, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Line + "\n")
	}
	return b.String()
}

func baseReq() BuildRequest {
	return BuildRequest{ImageID: "ubuntu-24.04", Cluster: "lab", Node: "pve1", TemplateName: "ubuntu-test", Apps: []string{"git"}}
}

func TestBuildJob(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		keep       string
		req        func(*BuildRequest)
		wantStatus jobs.Status
		wantLog    []string
		wantErr    string
		keepDir    bool
	}{
		{name: "success", mode: "ok", keep: "on_failure", wantStatus: jobs.StatusSucceeded,
			wantLog: []string{"==> packer init", "init ok", "validate ok", "==> proxmox-iso.image: Creating VM",
				"leaked token=<redacted> password=<redacted>", "warning on stderr", "==> artifact 0 id: 9001",
				"apps:     curl, htop, git"}},
		{name: "packer failure keeps workdir", mode: "fail", keep: "on_failure", wantStatus: jobs.StatusFailed,
			wantLog: []string{"ERROR: Build 'proxmox-iso.image' errored"}, wantErr: "packer build exited with code 1", keepDir: true},
		{name: "always keep", mode: "ok", keep: "always", wantStatus: jobs.StatusSucceeded, keepDir: true},
		{name: "unknown cluster", mode: "ok", keep: "never", req: func(r *BuildRequest) { r.Cluster = "other" },
			wantStatus: jobs.StatusFailed, wantErr: "unknown cluster"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newJobEnv(t, tt.mode, tt.keep)
			req := baseReq()
			if tt.req != nil {
				tt.req(&req)
			}
			b, err := e.svc.Submit(context.Background(), req, "alice")
			if err != nil {
				t.Fatal(err)
			}
			j := e.wait(t, b.JobID)
			if j.Status != tt.wantStatus {
				t.Fatalf("status %s (%s), want %s\n%s", j.Status, j.Error, tt.wantStatus, e.logs(t, j.ID))
			}
			if tt.wantErr != "" && !strings.Contains(j.Error, tt.wantErr) {
				t.Fatalf("error %q, want %q", j.Error, tt.wantErr)
			}
			logs := e.logs(t, j.ID)
			for _, w := range tt.wantLog {
				if !strings.Contains(logs, w) {
					t.Errorf("log missing %q:\n%s", w, logs)
				}
			}
			if strings.Contains(logs, fakeToken) {
				t.Fatal("token leaked into job log")
			}
			build, err := e.svc.Build(context.Background(), b.ID)
			if err != nil {
				t.Fatal(err)
			}
			if build.Status != tt.wantStatus {
				t.Fatalf("build row status %s", build.Status)
			}
			dir := filepath.Join(e.work, "builds", b.ID)
			_, statErr := os.Stat(dir)
			if tt.keepDir != (statErr == nil) {
				t.Fatalf("workdir exists=%v, want %v", statErr == nil, tt.keepDir)
			}
			if tt.wantStatus != jobs.StatusSucceeded {
				return
			}
			var res BuildResult
			if err := json.Unmarshal(j.Result, &res); err != nil || res.TemplateID != "9001" {
				t.Fatalf("result %s: %v", j.Result, err)
			}
			if build.ArtifactID != "9001" || strings.Join(build.Apps, ",") != "curl,htop,git" {
				t.Fatalf("build row %+v", build)
			}
			pw, err := e.svc.BuildPassword(context.Background(), b.ID)
			if err != nil || len(pw) != 24 {
				t.Fatalf("build password: %v", err)
			}
			args, _ := os.ReadFile(filepath.Join(e.bin, "args"))
			if want := "init .\nvalidate .\nbuild -color=false -machine-readable -on-error=cleanup .\n"; string(args) != want {
				t.Fatalf("argv = %q", args)
			}
			if strings.Contains(string(args), fakeToken) || strings.Contains(string(args), pw) {
				t.Fatal("secret in argv")
			}
			env, _ := os.ReadFile(filepath.Join(e.bin, "env"))
			if strings.TrimSpace(string(env)) != "PKR_VAR_build_password PROXMOX_TOKEN PROXMOX_URL PROXMOX_USERNAME" {
				t.Fatalf("env names = %q", env)
			}
		})
	}
}

func TestBuildJobCancel(t *testing.T) {
	e := newJobEnv(t, "hang", "never")
	b, err := e.svc.Submit(context.Background(), baseReq(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(e.logs(t, b.JobID), "Creating VM") {
		if time.Now().After(deadline) {
			t.Fatal("build did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := e.mgr.Cancel(context.Background(), b.JobID); err != nil {
		t.Fatal(err)
	}
	j := e.wait(t, b.JobID)
	if j.Status != jobs.StatusCanceled {
		t.Fatalf("status %s", j.Status)
	}
	if logs := e.logs(t, j.ID); !strings.Contains(logs, "interrupted, deleting VM") {
		t.Fatalf("packer did not get an interrupt:\n%s", logs)
	}
	build, _ := e.svc.Build(context.Background(), b.ID)
	if build.Status != jobs.StatusCanceled {
		t.Fatalf("build row status %s", build.Status)
	}
}

func TestSubmitValidation(t *testing.T) {
	e := newJobEnv(t, "ok", "never")
	tests := []struct {
		name  string
		mod   func(*BuildRequest)
		field string
	}{
		{"unknown image", func(r *BuildRequest) { r.ImageID = "nope" }, "image_id"},
		{"bad template name", func(r *BuildRequest) { r.TemplateName = "bad name;" }, "template_name"},
		{"bad node", func(r *BuildRequest) { r.Node = "" }, "node"},
		{"bad vmid", func(r *BuildRequest) { r.VMID = 5 }, "vm_id"},
		{"bad disk", func(r *BuildRequest) { r.Disk = "lots" }, "disk"},
		{"windows app on linux", func(r *BuildRequest) { r.Apps = []string{"sysinternals"} }, "apps"},
		{"windows needs iso", func(r *BuildRequest) { r.ImageID = "windows-11"; r.Apps = nil }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseReq()
			tt.mod(&req)
			_, err := e.svc.Submit(context.Background(), req, "alice")
			if tt.field == "" {
				// windows-11 ships a suggested iso_file, so it is accepted.
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var fe FieldErrors
			if !errors.As(err, &fe) || fe[tt.field] == "" {
				t.Fatalf("err = %v, want field %s", err, tt.field)
			}
		})
	}
}

func TestDownload(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create(exeName())
	_, _ = w.Write([]byte("#!/bin/sh\necho fake\n"))
	_ = zw.Close()
	sum := sha256.Sum256(zb.Bytes())
	zipName := "packer_1.2.3_" + runtime.GOOS + "_" + runtime.GOARCH + ".zip"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/packer/1.2.3/" + zipName:
			_, _ = w.Write(zb.Bytes())
		case "/packer/1.2.3/packer_1.2.3_SHA256SUMS":
			_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  " + zipName + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	tests := []struct {
		name    string
		pin     string
		wantErr string
	}{
		{"sums file", "", ""},
		{"pinned", hex.EncodeToString(sum[:]), ""},
		{"pin mismatch", strings.Repeat("0", 64), "checksum mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.PackerConfig{WorkDir: t.TempDir(), Version: "1.2.3", VersionSHA256: tt.pin, ReleasesURL: ts.URL}
			p, err := Download(context.Background(), cfg, ts.Client())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(p); !strings.Contains(string(b), "echo fake") {
				t.Fatalf("binary content %q", b)
			}
		})
	}
	if _, err := FindBinary(context.Background(), config.PackerConfig{Binary: "/nonexistent/packer"}, nil); err == nil {
		t.Fatal("missing binary accepted")
	}
}
