package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CoreNamespace is the namespace of the foundation tables (settings, jobs,
// job_logs). It is always migrated first.
const CoreNamespace = "core"

//go:embed migrations/*.sql
var coreMigrations embed.FS

func init() {
	sub, err := fs.Sub(coreMigrations, "migrations")
	if err != nil {
		panic(err)
	}
	RegisterMigrations(CoreNamespace, sub)
}

// Migration is a single parsed migration file.
type Migration struct {
	Namespace string
	Version   int
	Name      string
	SQL       string
}

// Registry holds migration sources keyed by namespace.
type Registry struct {
	mu      sync.Mutex
	sources map[string]fs.FS
}

// NewRegistry returns an empty registry (useful in tests).
func NewRegistry() *Registry { return &Registry{sources: map[string]fs.FS{}} }

var defaultRegistry = NewRegistry()

// RegisterMigrations registers the *.sql files at the root of fsys under
// namespace in the default registry. It panics on duplicate namespaces so
// conflicts are caught at startup. Call it from an init function.
func RegisterMigrations(namespace string, fsys fs.FS) {
	if err := defaultRegistry.Register(namespace, fsys); err != nil {
		panic(err)
	}
}

// Register adds a namespace to r.
func (r *Registry) Register(namespace string, fsys fs.FS) error {
	if namespace == "" || strings.ContainsAny(namespace, " \t/") {
		return fmt.Errorf("store: invalid migration namespace %q", namespace)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.sources[namespace]; dup {
		return fmt.Errorf("store: migration namespace %q registered twice", namespace)
	}
	r.sources[namespace] = fsys
	return nil
}

// Namespaces returns registered namespaces in apply order (core first, then
// alphabetical).
func (r *Registry) Namespaces() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.sources))
	for n := range r.sources {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == CoreNamespace || names[j] == CoreNamespace {
			return names[i] == CoreNamespace
		}
		return names[i] < names[j]
	})
	return names
}

// Load parses all migrations for namespace in version order.
func (r *Registry) Load(namespace string) ([]Migration, error) {
	r.mu.Lock()
	fsys := r.sources[namespace]
	r.mu.Unlock()
	if fsys == nil {
		return nil, fmt.Errorf("store: unknown namespace %q", namespace)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("store: read %s migrations: %w", namespace, err)
	}
	var out []Migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".sql" {
			continue
		}
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("store: %s/%s: name must be NNNN_description.sql", namespace, e.Name())
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("store: %s: duplicate version %d (%s, %s)", namespace, v, prev, e.Name())
		}
		seen[v] = e.Name()
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Namespace: namespace, Version: v, Name: e.Name(), SQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Migrate applies pending migrations from the default registry.
func Migrate(ctx context.Context, db *DB) error { return defaultRegistry.Migrate(ctx, db) }

// Migrate applies all pending migrations in r to db.
func (r *Registry) Migrate(ctx context.Context, db *DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			namespace  TEXT    NOT NULL,
			version    INTEGER NOT NULL,
			name       TEXT    NOT NULL,
			applied_at INTEGER NOT NULL,
			PRIMARY KEY (namespace, version)
		)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	for _, ns := range r.Namespaces() {
		migs, err := r.Load(ns)
		if err != nil {
			return err
		}
		applied, err := appliedVersions(ctx, db, ns)
		if err != nil {
			return err
		}
		for _, m := range migs {
			if applied[m.Version] {
				continue
			}
			if err := db.Tx(ctx, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx,
					`INSERT INTO schema_migrations (namespace, version, name, applied_at) VALUES (?, ?, ?, ?)`,
					m.Namespace, m.Version, m.Name, time.Now().UTC().UnixMilli())
				return err
			}); err != nil {
				return fmt.Errorf("store: migration %s/%s: %w", m.Namespace, m.Name, err)
			}
		}
	}
	return nil
}

func appliedVersions(ctx context.Context, db *DB, ns string) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations WHERE namespace = ?`, ns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}
