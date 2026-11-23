package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

const testPass = "test-passphrase-not-real"

var testNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type env struct {
	cfg  *config.Config
	root string
}

// newEnv creates a data dir with a config file, a migrated database holding
// a sealed setting, a master key and a catalog dir.
func newEnv(t *testing.T) env {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`data_dir: ./data
server: {listen: "127.0.0.1:0"}
catalog: {dirs: [./catalog]}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "catalog", "linux"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "catalog", "linux", "ubuntu.pkr.hcl"), "source v1")
	ctx := context.Background()
	sealer, err := secrets.OpenSealer(KeyFile(cfg))
	if err != nil {
		t.Fatal(err)
	}
	db := openDB(t, cfg)
	defer db.Close()
	sealed, _ := secrets.EncryptString(sealer, "proxmox-token-fake", "test:aad")
	if err := db.SetSetting(ctx, "test.sealed", sealed); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "test.plain", "original"); err != nil {
		t.Fatal(err)
	}
	return env{cfg: cfg, root: root}
}

func openDB(t *testing.T, cfg *config.Config) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, cfg.Database.Path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setting(t *testing.T, cfg *config.Config, key string) string {
	t.Helper()
	db := openDB(t, cfg)
	defer db.Close()
	v, err := db.GetSetting(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (e env) engine(pass string) *Engine {
	return &Engine{Cfg: e.cfg, AppVersion: "v-test", Passphrase: []byte(pass), KDF: testKDF}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	oldKey, _ := os.ReadFile(KeyFile(e.cfg))

	archive, err := e.engine(testPass).Backup(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(archive) != e.cfg.Backup.Dir || !ValidName(filepath.Base(archive)) {
		t.Fatalf("archive path %s", archive)
	}
	if fi, _ := os.Stat(archive); fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode %v", fi.Mode())
	}
	raw, _ := os.ReadFile(archive)
	if bytes.Contains(raw, []byte("proxmox")) || bytes.Contains(raw, []byte("original")) || bytes.Contains(raw, oldKey) {
		t.Fatal("archive is not encrypted")
	}

	// Change everything after the backup: data, catalog, master key (new host).
	db := openDB(t, e.cfg)
	_ = db.SetSetting(ctx, "test.plain", "changed")
	_ = db.Close()
	writeFile(t, filepath.Join(e.root, "catalog", "linux", "ubuntu.pkr.hcl"), "source v2")
	writeFile(t, filepath.Join(e.root, "catalog", "extra.txt"), "new")
	if err := os.Remove(KeyFile(e.cfg)); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.OpenSealer(KeyFile(e.cfg)); err != nil { // generates a different key
		t.Fatal(err)
	}

	st, err := e.engine(testPass).Stage(ctx, archive, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Cleanup()
	m := st.Manifest
	if m.AppVersion != "v-test" || !m.IncludesMasterKey || m.Schema["core"] != 1 || m.Schema["audit"] != 1 ||
		!m.HasFile("perfectimage.db") || !m.HasFile("config.yaml") || !m.HasFile("catalog/0/linux/ubuntu.pkr.hcl") {
		t.Fatalf("manifest %+v", m)
	}
	res, err := e.engine(testPass).ApplyOffline(ctx, st, DefaultRestoreOptions)
	if err != nil {
		t.Fatal(err)
	}
	if res.SafetyBackup == "" || !strings.Contains(filepath.Base(res.SafetyBackup), "pre-restore-") {
		t.Fatalf("safety backup %q", res.SafetyBackup)
	}

	if got := setting(t, e.cfg, "test.plain"); got != "original" {
		t.Fatalf("setting after restore = %q", got)
	}
	newKey, _ := os.ReadFile(KeyFile(e.cfg))
	if !bytes.Equal(newKey, oldKey) {
		t.Fatal("master key not restored")
	}
	sealer, err := secrets.OpenSealer(KeyFile(e.cfg))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := secrets.DecryptString(sealer, setting(t, e.cfg, "test.sealed"), "test:aad"); err != nil || pt != "proxmox-token-fake" {
		t.Fatalf("sealed secret after restore: %q %v", pt, err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.root, "catalog", "linux", "ubuntu.pkr.hcl")); string(b) != "source v1" {
		t.Fatalf("catalog not restored: %q", b)
	}
	if _, err := os.Stat(filepath.Join(e.root, "catalog", "extra.txt")); !os.IsNotExist(err) {
		t.Fatal("catalog dir not replaced")
	}
	if _, err := os.Stat(e.cfg.Path() + ".restored"); err != nil {
		t.Fatal("config not written for review")
	}
	matches, _ := filepath.Glob(KeyFile(e.cfg) + ".pre-restore-*")
	if len(matches) != 1 {
		t.Fatalf("old key not kept aside: %v", matches)
	}

	// The safety backup restores the post-backup state.
	st2, err := e.engine(testPass).Stage(ctx, res.SafetyBackup, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Cleanup()
	if _, err := e.engine(testPass).ApplyOffline(ctx, st2, RestoreOptions{MasterKey: true, SkipSafetyBackup: true}); err != nil {
		t.Fatal(err)
	}
	if got := setting(t, e.cfg, "test.plain"); got != "changed" {
		t.Fatalf("after restoring safety backup = %q", got)
	}
}

func TestRestoreFailures(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	archive, err := e.engine(testPass).Backup(ctx, filepath.Join(e.root, "out", "manual.pibak"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(archive)
	tampered := filepath.Join(e.root, "tampered.pibak")
	b := append([]byte(nil), raw...)
	b[len(b)/2] ^= 0x40
	writeFile(t, tampered, string(b))
	truncated := filepath.Join(e.root, "truncated.pibak")
	writeFile(t, truncated, string(raw[:len(raw)-100]))

	tests := []struct {
		name, src, pass string
		want            error
	}{
		{"wrong passphrase", archive, "not-the-passphrase", ErrWrongPassphrase},
		{"tampered", tampered, testPass, ErrCorrupt},
		{"truncated", truncated, testPass, ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := e.engine(tt.pass).Restore(ctx, tt.src)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			// Nothing was touched: data intact, no safety backup, no staging left.
			if got := setting(t, e.cfg, "test.plain"); got != "original" {
				t.Fatalf("data changed: %q", got)
			}
			list, _ := List(e.cfg.Backup.Dir)
			if len(list) != 0 {
				t.Fatalf("unexpected backups %v", list)
			}
			left, _ := filepath.Glob(filepath.Join(e.cfg.DataDir, ".restore-*"))
			if len(left) != 0 {
				t.Fatalf("staging dirs left: %v", left)
			}
		})
	}
}

func TestRestoreRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	db := openDB(t, e.cfg)
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (namespace, version, name, applied_at) VALUES ('core', 99, '0099_future.sql', 0)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	archive, err := e.engine(testPass).Backup(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	db = openDB(t, e.cfg)
	_, _ = db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 99`)
	_ = db.Close()

	if _, err := e.engine(testPass).Stage(ctx, archive, false); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("got %v", err)
	}
	st, err := e.engine(testPass).Stage(ctx, archive, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Cleanup()
	if !strings.Contains(strings.Join(st.Warnings, ";"), "forced") {
		t.Fatalf("warnings %v", st.Warnings)
	}
}

func TestBackupWithoutMasterKey(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	eng := e.engine(testPass)
	f := false
	eng.IncludeMasterKey = &f
	archive, err := eng.Backup(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := e.engine(testPass).Stage(ctx, archive, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Cleanup()
	if st.Manifest.IncludesMasterKey || st.Manifest.HasFile(entryMasterKey) ||
		!strings.Contains(strings.Join(st.Warnings, ";"), "master key") {
		t.Fatalf("manifest %+v warnings %v", st.Manifest, st.Warnings)
	}
}

func TestExtractRejectsUnsafeEntries(t *testing.T) {
	for _, name := range []string{"../evil", "/etc/passwd", "catalog/../../x", `catalog\..\x`, "unexpected.txt", "C:/x"} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			aw, err := newArchiveWriter(&buf, []byte(testPass), testKDF, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if err := aw.addBytes(name, []byte("x")); err != nil {
				t.Fatal(err)
			}
			if err := aw.finish(&Manifest{Format: ManifestFormat}); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if _, err := extract(&buf, []byte(testPass), dir); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestLiveRestore(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	live := openDB(t, e.cfg)
	defer live.Close()
	as, err := auditlog.New(ctx, live, auditlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close(ctx)
	_ = as.Record(ctx, audit.Event{Action: "before.backup"})
	_ = as.Flush(ctx)

	eng := e.engine(testPass)
	eng.LiveDB = live
	archive, err := eng.Backup(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	_ = live.SetSetting(ctx, "test.plain", "changed-live")
	_ = as.Record(ctx, audit.Event{Action: "after.backup"})
	_ = as.Flush(ctx)

	st, err := eng.Stage(ctx, archive, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Cleanup()
	if _, err := eng.ApplyLive(ctx, st, RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	// The open connection pool sees the restored content.
	if v, _ := live.GetSetting(ctx, "test.plain"); v != "original" {
		t.Fatalf("live setting %q", v)
	}
	if err := as.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	_ = as.Record(ctx, audit.Event{Action: "backup.restore"})
	_ = as.Flush(ctx)
	res, err := as.Verify(ctx)
	if err != nil || !res.OK || res.Checked != 2 {
		t.Fatalf("audit chain after live restore %+v %v", res, err)
	}
}

func TestPruneAndList(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"perfectimage-20260101T000000Z.pibak", "perfectimage-20260102T000000Z.pibak", "perfectimage-20260103T000000Z.pibak",
		"pre-restore-20260101T000000Z.pibak", "pre-restore-20260102T000000Z.pibak", "manual.pibak", "notes.txt",
	}
	for i, n := range names {
		p := filepath.Join(dir, n)
		writeFile(t, p, "x")
		ts := testNow.AddDate(0, 0, i)
		_ = os.Chtimes(p, ts, ts)
	}
	_ = os.Chtimes(filepath.Join(dir, "pre-restore-20260102T000000Z.pibak"), testNow.AddDate(0, 0, 10), testNow.AddDate(0, 0, 10))
	deleted, err := Prune(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := "pre-restore-20260101T000000Z.pibak perfectimage-20260102T000000Z.pibak perfectimage-20260101T000000Z.pibak"
	if got := strings.Join(deleted, " "); got != want {
		t.Fatalf("deleted %q want %q", got, want)
	}
	list, _ := List(dir)
	var got []string
	for _, b := range list {
		got = append(got, b.Name)
	}
	if strings.Join(got, " ") != "pre-restore-20260102T000000Z.pibak manual.pibak perfectimage-20260103T000000Z.pibak" {
		t.Fatalf("list %v", got)
	}
	for _, bad := range []string{"../x.pibak", "a/b.pibak", ".hidden.pibak", "x.pibak.partial", ""} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q)", bad)
		}
	}
}
