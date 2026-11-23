package backup

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/cli"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/web"
)

type opsEnv struct {
	env
	ops   *Ops
	jobs  *jobs.Manager
	audit *auditlog.Store
	h     http.Handler
}

func newOpsEnv(t *testing.T) *opsEnv {
	t.Helper()
	ctx := context.Background()
	e := newEnv(t)
	db := openDB(t, e.cfg)
	t.Cleanup(func() { _ = db.Close() })
	sealer, err := secrets.OpenSealer(KeyFile(e.cfg))
	if err != nil {
		t.Fatal(err)
	}
	as, err := auditlog.New(ctx, db, auditlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.Close(context.Background()) })
	jm := jobs.New(db, jobs.Options{Workers: 1, PollInterval: 20 * time.Millisecond})
	ops := &Ops{cfg: e.cfg, db: db, sealer: sealer, jobs: jm, audit: as, auditStore: as,
		log: slog.New(slog.DiscardHandler), version: "v-test", kdf: testKDF}
	if err := jm.Register(JobType, ops); err != nil {
		t.Fatal(err)
	}
	if err := jm.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jm.Stop(context.Background()) })
	srv := web.NewServer(web.Options{Audit: as, Jobs: jm})
	srv.SetAuthenticator(auth.DevAllowAll{})
	srv.SetAuthorizer(auth.DevAllowAll{})
	srv.AddModule(&module{svc: ops})
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return &opsEnv{env: e, ops: ops, jobs: jm, audit: as, h: h}
}

func (o *opsEnv) do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	req.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	o.h.ServeHTTP(w, req)
	return w
}

func (o *opsEnv) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return o.do(t, req)
}

func (o *opsEnv) actions(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	_ = o.audit.Flush(ctx)
	var out []string
	_ = o.audit.Each(ctx, auditlog.Filter{}, func(e auditlog.Entry) error {
		out = append(out, e.Action+":"+string(e.Outcome))
		return nil
	})
	return strings.Join(out, " ")
}

func uploadReq(t *testing.T, archive []byte, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("archive", "upload.pibak")
	_, _ = fw.Write(archive)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/settings/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestOpsBackupJobDownloadAndUploadRestore(t *testing.T) {
	ctx := context.Background()
	o := newOpsEnv(t)

	// Without a passphrase, "run now" is refused.
	if w := o.post(t, "/settings/backup/run", nil); !strings.Contains(w.Body.String(), "passphrase not configured") {
		t.Fatalf("run without passphrase: %s", w.Body.String())
	}
	if w := o.post(t, "/settings/backup/passphrase", url.Values{"passphrase": {"short"}, "confirm": {"short"}}); !strings.Contains(w.Body.String(), "at least") {
		t.Fatalf("short passphrase: %s", w.Body.String())
	}
	if w := o.post(t, "/settings/backup/passphrase", url.Values{"passphrase": {testPass}, "confirm": {testPass}}); !strings.Contains(w.Body.String(), "saved") {
		t.Fatalf("set passphrase: %s", w.Body.String())
	}
	if raw, _ := o.ops.db.GetSetting(ctx, passphraseKey); strings.Contains(raw, testPass) {
		t.Fatal("passphrase stored in plaintext")
	}

	w := o.post(t, "/settings/backup/run", nil)
	jobID := strings.TrimPrefix(w.Header().Get("HX-Redirect"), "/jobs/")
	if jobID == "" {
		t.Fatalf("run: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	var job *jobs.Job
	deadline := time.Now().Add(10 * time.Second)
	for {
		job, _ = o.jobs.Get(ctx, jobID)
		if job != nil && job.Status.Terminal() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backup job did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if job.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", job.Status, job.Error)
	}
	list, _ := List(o.cfg.Backup.Dir)
	if len(list) != 1 {
		t.Fatalf("backups %v", list)
	}
	name := list[0].Name

	page := o.do(t, httptest.NewRequest("GET", "/settings/backup", nil))
	if page.Code != 200 || !strings.Contains(page.Body.String(), name) || !strings.Contains(page.Body.String(), "master key") {
		t.Fatalf("page %d %s", page.Code, page.Body.String())
	}
	dl := o.do(t, httptest.NewRequest("GET", "/settings/backup/download/"+name, nil))
	if dl.Code != 200 || dl.Body.Len() != int(list[0].Size) {
		t.Fatalf("download %d len %d", dl.Code, dl.Body.Len())
	}
	if w := o.do(t, httptest.NewRequest("GET", "/settings/backup/download/..%2Fconfig.yaml", nil)); w.Code == 200 {
		t.Fatal("path traversal in download")
	}
	archive := dl.Body.Bytes()

	_ = o.ops.db.SetSetting(ctx, "test.plain", "changed")

	// Confirmation is required; wrong passphrase and tampered archives fail
	// without changing anything.
	if w := o.do(t, uploadReq(t, archive, map[string]string{"confirm": "yes"})); !strings.Contains(w.Body.String(), "Type RESTORE") {
		t.Fatalf("no confirmation: %s", w.Body.String())
	}
	if w := o.do(t, uploadReq(t, archive, map[string]string{"confirm": "RESTORE", "passphrase": "wrong-passphrase"})); !strings.Contains(w.Body.String(), "Wrong passphrase") {
		t.Fatalf("wrong passphrase: %s", w.Body.String())
	}
	bad := append([]byte(nil), archive...)
	bad[len(bad)/2] ^= 1
	if w := o.do(t, uploadReq(t, bad, map[string]string{"confirm": "RESTORE"})); !strings.Contains(w.Body.String(), "corrupted") {
		t.Fatalf("tampered: %s", w.Body.String())
	}
	if v, _ := o.ops.db.GetSetting(ctx, "test.plain"); v != "changed" || o.ops.RestartRequired() != "" {
		t.Fatal("failed restore changed state")
	}

	w = o.do(t, uploadReq(t, archive, map[string]string{"confirm": "RESTORE"}))
	if !strings.Contains(w.Body.String(), "Restore complete") {
		t.Fatalf("restore: %s", w.Body.String())
	}
	if v, _ := o.ops.db.GetSetting(ctx, "test.plain"); v != "original" {
		t.Fatalf("setting after restore %q", v)
	}
	if o.ops.RestartRequired() == "" {
		t.Fatal("restart not required after restore")
	}
	list, _ = List(o.cfg.Backup.Dir)
	var safety bool
	for _, b := range list {
		safety = safety || b.PreRestore
	}
	if !safety {
		t.Fatalf("no safety backup in %v", list)
	}
	// The restored audit log contains the pre-backup history plus the restore
	// event, and the chain verifies.
	acts := o.actions(t)
	if !strings.HasSuffix(acts, "backup.restore:success") || strings.Contains(acts, "backup.download") {
		t.Fatalf("audit after restore: %s", acts)
	}
	if res, err := o.audit.Verify(ctx); err != nil || !res.OK {
		t.Fatalf("verify %+v %v", res, err)
	}
	// Safety backup holds the pre-restore audit trail (download, failed restores).
	st, err := (&Engine{Cfg: o.cfg, Passphrase: []byte(testPass), KDF: testKDF}).Stage(ctx, filepath.Join(o.cfg.Backup.Dir, safetyName(list)), false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Cleanup()
}

func safetyName(list []Info) string {
	for _, b := range list {
		if b.PreRestore {
			return b.Name
		}
	}
	return ""
}

func TestRestoreRequiresBackupRun(t *testing.T) {
	o := newOpsEnv(t)
	srv := web.NewServer(web.Options{Audit: o.audit})
	p := auth.Principal{ID: "u", Username: "settings-only", Permissions: []rbac.Permission{rbac.SettingsManage}}
	srv.SetAuthenticator(authFunc(func(*http.Request) (*auth.Principal, error) { q := p; return &q, nil }))
	srv.AddModule(&module{svc: o.ops})
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, uploadReq(t, []byte("x"), map[string]string{"confirm": "RESTORE"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("code %d", w.Code)
	}
	if acts := o.actions(t); !strings.Contains(acts, "backup.restore:denied") {
		t.Fatalf("audit %s", acts)
	}
}

func TestCLIBackupRestore(t *testing.T) {
	e := newEnv(t)
	pf := filepath.Join(e.root, "pass.txt")
	writeFile(t, pf, testPass+"\n")
	var out, errb bytes.Buffer
	cenv := &cli.Env{Stdout: &out, Stderr: &errb, Version: "v-cli"}
	ctx := context.Background()
	// The CLI uses the default KDF; that is slower but exercises the real path.
	if code := cli.Main(ctx, cenv, []string{"backup", "--config", e.cfg.Path(), "--passphrase-file", pf}); code != 0 {
		t.Fatalf("backup exit %d: %s", code, errb.String())
	}
	archive := strings.TrimSpace(out.String())
	if !strings.HasSuffix(archive, Ext) || !strings.Contains(errb.String(), "master key") {
		t.Fatalf("backup output %q / %q", archive, errb.String())
	}
	db := openDB(t, e.cfg)
	_ = db.SetSetting(ctx, "test.plain", "changed")
	_ = db.Close()

	out.Reset()
	errb.Reset()
	if code := cli.Main(ctx, cenv, []string{"restore", "--config", e.cfg.Path(), "--in", archive, "--passphrase-file", pf}); code != 0 {
		t.Fatalf("verify exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "Archive verified") || !strings.Contains(out.String(), "--yes") {
		t.Fatalf("verify output %s", out.String())
	}
	if got := setting(t, e.cfg, "test.plain"); got != "changed" {
		t.Fatal("restore without --yes changed data")
	}

	wrong := filepath.Join(e.root, "wrong.txt")
	writeFile(t, wrong, "nope-nope-nope")
	if code := cli.Main(ctx, cenv, []string{"restore", "--config", e.cfg.Path(), "--in", archive, "--passphrase-file", wrong, "--yes"}); code != 1 ||
		!strings.Contains(errb.String(), "wrong passphrase") {
		t.Fatalf("wrong passphrase exit %d: %s", code, errb.String())
	}

	out.Reset()
	errb.Reset()
	t.Setenv(PassphraseEnv, testPass)
	if code := cli.Main(ctx, cenv, []string{"restore", "--config", e.cfg.Path(), "--in", archive, "--yes"}); code != 0 {
		t.Fatalf("restore exit %d: %s", code, errb.String())
	}
	if got := setting(t, e.cfg, "test.plain"); got != "original" {
		t.Fatalf("after CLI restore %q", got)
	}
	if !strings.Contains(out.String(), "Safety backup") || !strings.Contains(out.String(), "Restore complete") {
		t.Fatalf("restore output %s", out.String())
	}
	// The restore was appended to the restored audit log.
	db = openDB(t, e.cfg)
	defer db.Close()
	as, err := auditlog.New(ctx, db, auditlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close(ctx)
	got, _, _ := as.Query(ctx, auditlog.Filter{Action: "backup.restore"})
	if len(got) != 1 || !strings.HasPrefix(got[0].Actor, "cli") {
		t.Fatalf("audit %+v", got)
	}
	if res, _ := as.Verify(ctx); !res.OK {
		t.Fatalf("verify %+v", res)
	}

	if code := cli.Main(ctx, cenv, []string{"restore", "--config", e.cfg.Path()}); code != 2 {
		t.Fatalf("missing --in exit %d", code)
	}
	_, _ = io.Copy(io.Discard, &out)
	_ = os.Remove(archive)
}

type authFunc func(*http.Request) (*auth.Principal, error)

func (f authFunc) Authenticate(r *http.Request) (*auth.Principal, error) { return f(r) }

// A synchronizer-token CSRF middleware may parse the multipart form before
// the handler; the restore upload must still work.
func TestUploadAfterFormParsed(t *testing.T) {
	ctx := context.Background()
	o := newOpsEnv(t)
	archive, err := o.ops.engine([]byte(testPass)).Backup(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(archive)
	_ = o.ops.db.SetSetting(ctx, "test.plain", "changed")
	req := uploadReq(t, raw, map[string]string{"confirm": "RESTORE", "passphrase": testPass, "csrf_token": "x"})
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	if w := o.do(t, req); !strings.Contains(w.Body.String(), "Restore complete") {
		t.Fatalf("restore: %s", w.Body.String())
	}
	if v, _ := o.ops.db.GetSetting(ctx, "test.plain"); v != "original" {
		t.Fatalf("setting %q", v)
	}
}
