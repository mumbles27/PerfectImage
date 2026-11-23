// Package store opens the SQLite database and runs embedded migrations.
//
// Domain packages own their tables: they embed a directory of ordered SQL
// files and register it from an init function:
//
//	//go:embed migrations/*.sql
//	var migrationsFS embed.FS
//
//	func init() {
//		sub, _ := fs.Sub(migrationsFS, "migrations")
//		store.RegisterMigrations("auth", sub)
//	}
//
// Files are named NNNN_description.sql (e.g. 0001_users.sql) and are applied
// in numeric order, once, inside a transaction. Applied migrations must never
// be edited; add a new file instead.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go)
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// DB wraps *sql.DB for the PerfectImage database.
type DB struct {
	*sql.DB
	path string
}

// Options configures Open.
type Options struct {
	BusyTimeout time.Duration
}

// Open opens (creating if necessary) the SQLite database at path with WAL
// journaling, a busy timeout, foreign keys enabled and IMMEDIATE write
// transactions. It does not run migrations; call Migrate.
func Open(ctx context.Context, path string, opts Options) (*DB, error) {
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = 5 * time.Second
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("store: create dir: %w", err)
	}
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", opts.BusyTimeout.Milliseconds()))
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + filepath.ToSlash(path) + "?" + q.Encode()

	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	sqldb.SetMaxOpenConns(8)
	sqldb.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	// Restrict DB file permissions (no-op semantics on Windows).
	_ = os.Chmod(path, 0o600)
	return &DB{DB: sqldb, path: path}, nil
}

// Path returns the database file path.
func (db *DB) Path() string { return db.path }

// Tx runs fn inside a transaction, committing on success.
func (db *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// GetSetting returns the value for key or ErrNotFound.
func (db *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting upserts key=value. Do not store plaintext secrets here; seal them
// with internal/secrets first.
func (db *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().UTC().UnixMilli())
	return err
}

// DeleteSetting removes key (no error if absent).
func (db *DB) DeleteSetting(ctx context.Context, key string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}
