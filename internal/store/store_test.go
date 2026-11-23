package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "test.db"), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpenPragmas(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q, %v", mode, err)
	}
	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d, %v", fk, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(db.Path())
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("db perms = %v", fi.Mode().Perm())
		}
	}
}

func TestMigrateCoreAndSettings(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Idempotent.
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate again: %v", err)
	}
	if _, err := db.GetSetting(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSetting missing: %v", err)
	}
	if err := db.SetSetting(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, err := db.GetSetting(ctx, "k"); err != nil || v != "v2" {
		t.Fatalf("GetSetting = %q, %v", v, err)
	}
	if err := db.DeleteSetting(ctx, "k"); err != nil {
		t.Fatal(err)
	}
}

func TestRegistry(t *testing.T) {
	tests := []struct {
		name    string
		files   fstest.MapFS
		wantErr bool
		tables  []string
	}{
		{
			name: "ordered",
			files: fstest.MapFS{
				"0002_b.sql":  {Data: []byte("ALTER TABLE widgets ADD COLUMN size INTEGER;")},
				"0001_a.sql":  {Data: []byte("CREATE TABLE widgets (id INTEGER PRIMARY KEY);")},
				"README.md":   {Data: []byte("ignored")},
				"0010_c.sql":  {Data: []byte("CREATE TABLE gadgets (id INTEGER PRIMARY KEY);")},
				"sub/0003.sq": {Data: []byte("ignored")},
			},
			tables: []string{"widgets", "gadgets"},
		},
		{
			name:    "bad name",
			files:   fstest.MapFS{"a.sql": {Data: []byte("SELECT 1;")}},
			wantErr: true,
		},
		{
			name: "duplicate version",
			files: fstest.MapFS{
				"0001_a.sql": {Data: []byte("SELECT 1;")},
				"1_b.sql":    {Data: []byte("SELECT 1;")},
			},
			wantErr: true,
		},
		{
			name:    "bad sql rolls back",
			files:   fstest.MapFS{"0001_a.sql": {Data: []byte("CREATE TABLE ok (id INTEGER); NOT SQL;")}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTest(t)
			r := NewRegistry()
			if err := r.Register("test", tt.files); err != nil {
				t.Fatal(err)
			}
			err := r.Migrate(context.Background(), db)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Migrate err = %v, wantErr %v", err, tt.wantErr)
			}
			for _, tbl := range tt.tables {
				var n int
				if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil || n != 1 {
					t.Errorf("table %s missing", tbl)
				}
			}
			if tt.name == "bad sql rolls back" {
				var n int
				_ = db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='ok'`).Scan(&n)
				if n != 0 {
					t.Error("failed migration was not rolled back")
				}
			}
		})
	}
}

func TestRegistryNamespaces(t *testing.T) {
	r := NewRegistry()
	for _, n := range []string{"zeta", CoreNamespace, "auth"} {
		if err := r.Register(n, fstest.MapFS{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Register("auth", fstest.MapFS{}); err == nil {
		t.Error("expected duplicate error")
	}
	if err := r.Register("bad name", fstest.MapFS{}); err == nil {
		t.Error("expected invalid name error")
	}
	got := r.Namespaces()
	want := []string{CoreNamespace, "auth", "zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Namespaces = %v, want %v", got, want)
		}
	}
}
