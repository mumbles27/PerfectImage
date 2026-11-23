package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// Archive file naming.
const (
	Ext              = ".pibak"
	scheduledPrefix  = "perfectimage-"
	preRestorePrefix = "pre-restore-"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.pibak$`)

// ValidName reports whether name is a plain backup file name (no path).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// ErrNewerSchema is returned when an archive comes from a newer schema than
// the database it would replace.
var ErrNewerSchema = errors.New("backup: archive schema is newer than this installation")

// Engine implements Service for one configuration.
type Engine struct {
	Cfg        *config.Config
	AppVersion string
	// Passphrase encrypts new archives and decrypts archives to restore.
	Passphrase []byte
	// IncludeMasterKey overrides cfg.Backup.IncludeMasterKey when non-nil.
	IncludeMasterKey *bool
	KDF              KDFParams
	Logger           *slog.Logger
	// LiveDB is the running service's database. When nil (CLI), the
	// database file is opened directly.
	LiveDB *store.DB
	Now    func() time.Time
}

var _ Service = (*Engine)(nil)

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) log() *slog.Logger {
	if e.Logger != nil {
		return e.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (e *Engine) kdf() KDFParams {
	if e.KDF == (KDFParams{}) {
		return DefaultKDF
	}
	return e.KDF
}

func (e *Engine) includeKey() bool {
	if e.IncludeMasterKey != nil {
		return *e.IncludeMasterKey
	}
	return e.Cfg.Backup.MasterKeyIncluded()
}

// KeyFile returns the configured master key path.
func KeyFile(cfg *config.Config) string {
	if cfg.Secrets.KeyFile != "" {
		return cfg.Secrets.KeyFile
	}
	return filepath.Join(cfg.DataDir, "secrets", secrets.DefaultKeyFileName)
}

// Backup implements Service. dest is a directory (a timestamped name is
// chosen) or a file path ending in .pibak.
func (e *Engine) Backup(ctx context.Context, dest string) (string, error) {
	return e.backup(ctx, dest, scheduledPrefix)
}

func (e *Engine) backup(ctx context.Context, dest, prefix string) (string, error) {
	if len(e.Passphrase) == 0 {
		return "", errors.New("backup: passphrase required")
	}
	if dest == "" {
		dest = e.Cfg.Backup.Dir
	}
	out := dest
	if !strings.HasSuffix(dest, Ext) {
		out = filepath.Join(dest, prefix+e.now().Format("20060102T150405Z")+Ext)
		if _, err := os.Stat(out); err == nil {
			out = strings.TrimSuffix(out, Ext) + "-" + randHex(3) + Ext
		}
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return "", fmt.Errorf("backup: create dir: %w", err)
	}
	tmpDir, err := os.MkdirTemp(filepath.Dir(out), ".backup-tmp-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	snap := filepath.Join(tmpDir, entryDB)
	if err := e.snapshot(ctx, snap); err != nil {
		return "", err
	}
	schema, err := schemaVersions(ctx, snap)
	if err != nil {
		return "", err
	}

	partial := out + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(partial)
		}
	}()
	aw, err := newArchiveWriter(f, e.Passphrase, e.kdf(), e.now())
	if err != nil {
		return "", err
	}
	host, _ := os.Hostname()
	m := &Manifest{Format: ManifestFormat, AppVersion: e.AppVersion, CreatedAt: e.now(), Host: host, Schema: schema}
	if err := aw.addFile(entryDB, snap); err != nil {
		return "", err
	}
	if p := e.Cfg.Path(); p != "" {
		if _, err := os.Stat(p); err == nil {
			if err := aw.addFile(entryConfig, p); err != nil {
				return "", err
			}
			m.ConfigPath = p
		}
	}
	// Directory i is stored as catalog/<i>/; missing dirs are skipped but
	// keep their index so restore maps archives back to the same position.
	m.CatalogDirs = append([]string(nil), e.Cfg.Catalog.Dirs...)
	for i, dir := range e.Cfg.Catalog.Dirs {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := aw.addDir(fmt.Sprintf("%s%d/", catalogPrefix, i), dir); err != nil {
			return "", fmt.Errorf("backup: catalog %s: %w", dir, err)
		}
	}
	if e.includeKey() {
		key, err := readMasterKey(KeyFile(e.Cfg))
		switch {
		case err == nil:
			err = aw.addBytes(entryMasterKey, key)
			clear(key)
			if err != nil {
				return "", err
			}
			m.IncludesMasterKey = true
		case errors.Is(err, os.ErrNotExist):
			e.log().Warn("backup: master key file not found; archive will not include it", "path", KeyFile(e.Cfg))
		default:
			return "", fmt.Errorf("backup: read master key: %w", err)
		}
	}
	if err := aw.finish(m); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(partial, out); err != nil {
		return "", err
	}
	ok = true
	return out, nil
}

// snapshot writes a consistent copy of the database with VACUUM INTO.
func (e *Engine) snapshot(ctx context.Context, dst string) error {
	db := e.LiveDB
	if db == nil {
		if _, err := os.Stat(e.Cfg.Database.Path); err != nil {
			return fmt.Errorf("backup: database: %w", err)
		}
		var err error
		db, err = store.Open(ctx, e.Cfg.Database.Path, store.Options{BusyTimeout: e.Cfg.Database.BusyTimeout})
		if err != nil {
			return err
		}
		defer db.Close()
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("backup: snapshot database: %w", err)
	}
	return os.Chmod(dst, 0o600)
}

// openReadOnly opens a SQLite file without modifying it.
func openReadOnly(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma="+url.QueryEscape("busy_timeout(5000)"))
}

// schemaVersions returns the newest applied migration per namespace.
func schemaVersions(ctx context.Context, dbPath string) (map[string]int, error) {
	db, err := openReadOnly(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT namespace, MAX(version) FROM schema_migrations GROUP BY namespace`)
	if err != nil {
		return nil, fmt.Errorf("backup: read schema versions: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var ns string
		var v int
		if err := rows.Scan(&ns, &v); err != nil {
			return nil, err
		}
		out[ns] = v
	}
	return out, rows.Err()
}

func integrityCheck(ctx context.Context, dbPath string) error {
	db, err := openReadOnly(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&res); err != nil {
		return fmt.Errorf("%w: database snapshot: %v", ErrCorrupt, err)
	}
	if res != "ok" {
		return fmt.Errorf("%w: database snapshot integrity check: %s", ErrCorrupt, res)
	}
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Staged is a decrypted, verified archive extracted to a private directory
// next to the database (so the final rename is atomic).
type Staged struct {
	Dir      string
	Manifest *Manifest
	// Warnings are non-fatal findings (version differences, missing key).
	Warnings []string
}

// DBPath is the staged database snapshot.
func (s *Staged) DBPath() string { return filepath.Join(s.Dir, entryDB) }

// Cleanup removes the staging directory.
func (s *Staged) Cleanup() { _ = os.RemoveAll(s.Dir) }

// Stage decrypts and fully verifies the archive at src: authenticated
// encryption, manifest file hashes, SQLite integrity and schema versions
// compared with the current database (newer schemas are refused unless
// force). The caller must Cleanup the result.
func (e *Engine) Stage(ctx context.Context, src string, force bool) (*Staged, error) {
	if len(e.Passphrase) == 0 {
		return nil, errors.New("backup: passphrase required")
	}
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return e.StageReader(ctx, f, force)
}

// StageReader is Stage for an archive stream.
func (e *Engine) StageReader(ctx context.Context, r io.Reader, force bool) (*Staged, error) {
	dbDir := filepath.Dir(e.Cfg.Database.Path)
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(dbDir, ".restore-")
	if err != nil {
		return nil, err
	}
	st := &Staged{Dir: dir}
	ok := false
	defer func() {
		if !ok {
			st.Cleanup()
		}
	}()
	if st.Manifest, err = extract(r, e.Passphrase, dir); err != nil {
		return nil, err
	}
	if err := integrityCheck(ctx, st.DBPath()); err != nil {
		return nil, err
	}
	snapSchema, err := schemaVersions(ctx, st.DBPath())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	for ns, v := range st.Manifest.Schema {
		if snapSchema[ns] != v {
			return nil, fmt.Errorf("%w: schema versions differ from the manifest", ErrCorrupt)
		}
	}
	if st.Manifest.AppVersion != e.AppVersion {
		st.Warnings = append(st.Warnings, fmt.Sprintf("archive was created by version %s; this is %s",
			st.Manifest.AppVersion, e.AppVersion))
	}
	current, err := e.currentSchema(ctx)
	if err != nil {
		return nil, err
	}
	var newer []string
	for ns, v := range st.Manifest.Schema {
		if cv, ok := current[ns]; ok && v > cv {
			newer = append(newer, fmt.Sprintf("%s %d > %d", ns, v, cv))
		}
	}
	sort.Strings(newer)
	if len(newer) > 0 {
		msg := strings.Join(newer, ", ")
		if !force {
			return nil, fmt.Errorf("%w (%s); upgrade PerfectImage first or force the restore", ErrNewerSchema, msg)
		}
		st.Warnings = append(st.Warnings, "forced restore of newer schema: "+msg)
	}
	if !st.Manifest.IncludesMasterKey {
		st.Warnings = append(st.Warnings, "archive does not include the master key: credentials sealed in it "+
			"can only be decrypted on the original host (or must be re-entered)")
	}
	ok = true
	return st, nil
}

func (e *Engine) currentSchema(ctx context.Context) (map[string]int, error) {
	if e.LiveDB != nil {
		rows, err := e.LiveDB.QueryContext(ctx, `SELECT namespace, MAX(version) FROM schema_migrations GROUP BY namespace`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var ns string
			var v int
			if err := rows.Scan(&ns, &v); err != nil {
				return nil, err
			}
			out[ns] = v
		}
		return out, rows.Err()
	}
	if _, err := os.Stat(e.Cfg.Database.Path); errors.Is(err, os.ErrNotExist) {
		return map[string]int{}, nil
	}
	return schemaVersions(ctx, e.Cfg.Database.Path)
}

// RestoreOptions selects what Apply restores besides the database.
type RestoreOptions struct {
	// MasterKey installs the archived master key (if present).
	MasterKey bool
	// Catalog replaces the configured catalog dirs with the archived ones
	// (the old dirs are kept as <dir>.pre-restore-<ts>).
	Catalog bool
	// OverwriteConfig replaces the config file (old kept as
	// <config>.pre-restore-<ts>). Otherwise the archived config is written to
	// <config>.restored for review.
	OverwriteConfig bool
	// SkipSafetyBackup skips the pre-restore backup of the current state.
	SkipSafetyBackup bool
}

// DefaultRestoreOptions restores the database, master key and catalog and
// writes the archived config next to the current one.
var DefaultRestoreOptions = RestoreOptions{MasterKey: true, Catalog: true}

// Result summarizes a restore.
type Result struct {
	Manifest     *Manifest
	SafetyBackup string
	Restored     []string
	Warnings     []string
}

// Restore implements Service: it restores src with DefaultRestoreOptions.
// The service must be stopped.
func (e *Engine) Restore(ctx context.Context, src string) error {
	st, err := e.Stage(ctx, src, false)
	if err != nil {
		return err
	}
	defer st.Cleanup()
	_, err = e.ApplyOffline(ctx, st, DefaultRestoreOptions)
	return err
}

// SafetyBackup writes a pre-restore backup of the current state to the
// backup dir. It returns "" if there is no database yet.
func (e *Engine) SafetyBackup(ctx context.Context) (string, error) {
	if e.LiveDB == nil {
		if _, err := os.Stat(e.Cfg.Database.Path); errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
	}
	p, err := e.backup(ctx, e.Cfg.Backup.Dir, preRestorePrefix)
	if err != nil {
		return "", fmt.Errorf("pre-restore safety backup: %w", err)
	}
	return p, nil
}

// ApplyOffline swaps in a staged archive while the service is stopped: it
// takes a safety backup, atomically renames the snapshot over the database
// (removing stale WAL/SHM files) and restores key, config and catalog.
func (e *Engine) ApplyOffline(ctx context.Context, st *Staged, opts RestoreOptions) (*Result, error) {
	if e.LiveDB != nil {
		return nil, errors.New("backup: ApplyOffline requires the service to be stopped")
	}
	res := &Result{Manifest: st.Manifest, Warnings: append([]string(nil), st.Warnings...)}
	if !opts.SkipSafetyBackup {
		p, err := e.SafetyBackup(ctx)
		if err != nil {
			return nil, err
		}
		res.SafetyBackup = p
	}
	dbPath := e.Cfg.Database.Path
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Remove(dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove %s: %w", dbPath+suffix, err)
		}
	}
	if err := os.Rename(st.DBPath(), dbPath); err != nil {
		return nil, fmt.Errorf("swap database: %w", err)
	}
	_ = os.Chmod(dbPath, 0o600)
	res.Restored = append(res.Restored, "database")
	if err := e.applyFiles(st, opts, res); err != nil {
		return res, err
	}
	return res, nil
}

// applyFiles restores the master key, config and catalog dirs.
func (e *Engine) applyFiles(st *Staged, opts RestoreOptions, res *Result) error {
	ts := e.now().Format("20060102T150405Z")
	if st.Manifest.IncludesMasterKey && opts.MasterKey {
		key, err := os.ReadFile(filepath.Join(st.Dir, filepath.FromSlash(entryMasterKey)))
		if err != nil {
			return err
		}
		changed, err := installMasterKey(KeyFile(e.Cfg), key, ts)
		clear(key)
		if err != nil {
			return fmt.Errorf("install master key: %w", err)
		}
		if changed {
			res.Restored = append(res.Restored, "master key")
		}
	}
	if st.Manifest.HasFile(entryConfig) {
		staged := filepath.Join(st.Dir, entryConfig)
		cur := e.Cfg.Path()
		switch {
		case cur == "":
			res.Warnings = append(res.Warnings, "no config path known; archived config not restored")
		case opts.OverwriteConfig:
			if err := keepAside(cur, ts); err != nil {
				return err
			}
			if err := copyFile(staged, cur); err != nil {
				return err
			}
			res.Restored = append(res.Restored, "config")
		default:
			if err := copyFile(staged, cur+".restored"); err != nil {
				return err
			}
			res.Warnings = append(res.Warnings, "archived config written to "+cur+".restored for review")
		}
	}
	if opts.Catalog {
		for i, src := range st.Manifest.CatalogDirs {
			stagedDir := filepath.Join(st.Dir, "catalog", fmt.Sprint(i))
			if _, err := os.Stat(stagedDir); err != nil {
				continue
			}
			if i >= len(e.Cfg.Catalog.Dirs) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("catalog dir %d (%s) has no configured target; skipped", i, src))
				continue
			}
			dst := e.Cfg.Catalog.Dirs[i]
			if err := keepAside(dst, ts); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			if err := moveDir(stagedDir, dst); err != nil {
				return fmt.Errorf("restore catalog %s: %w", dst, err)
			}
			res.Restored = append(res.Restored, "catalog "+dst)
		}
	}
	return nil
}

// keepAside renames p to p.pre-restore-<ts> if it exists.
func keepAside(p, ts string) error {
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return os.Rename(p, p+".pre-restore-"+ts)
}

// moveDir renames src to dst, falling back to a copy across filesystems.
func moveDir(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyFile(p, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp-" + randHex(4)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if serr := out.Sync(); err == nil {
		err = serr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// readMasterKey returns the raw master key, or an os.ErrNotExist error.
func readMasterKey(path string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return secrets.LoadOrCreateMasterKey(path)
}

// installMasterKey writes key to path unless the current key is identical.
// A different existing key is kept as path.pre-restore-<ts>.
func installMasterKey(path string, key []byte, ts string) (bool, error) {
	if len(key) != secrets.KeySize {
		return false, fmt.Errorf("%w: archived master key has %d bytes", ErrCorrupt, len(key))
	}
	if cur, err := readMasterKey(path); err == nil {
		same := bytes.Equal(cur, key)
		clear(cur)
		if same {
			return false, nil
		}
		if err := keepAside(path, ts); err != nil {
			return false, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		// Unreadable key (e.g. DPAPI blob from another machine): keep it aside.
		if err := keepAside(path, ts); err != nil {
			return false, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	return true, writeMasterKey(path, key)
}

// List returns the backups in dir, newest first.
func List(dir string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, de := range entries {
		if de.IsDir() || !ValidName(de.Name()) {
			continue
		}
		fi, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Name: de.Name(), Size: fi.Size(), ModTime: fi.ModTime(),
			PreRestore: strings.HasPrefix(de.Name(), preRestorePrefix)})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ModTime.After(out[j].ModTime)
		}
		return out[i].Name > out[j].Name
	})
	return out, nil
}

// Info describes a backup file.
type Info struct {
	Name       string
	Size       int64
	ModTime    time.Time
	PreRestore bool
}

// Prune keeps the newest keep archives of each kind (scheduled and
// pre-restore) in dir and deletes the rest. It returns the deleted names.
func Prune(dir string, keep int) ([]string, error) {
	list, err := List(dir)
	if err != nil {
		return nil, err
	}
	var deleted []string
	counts := map[bool]int{}
	for _, b := range list {
		if !strings.HasPrefix(b.Name, scheduledPrefix) && !b.PreRestore {
			continue // manually named archives are never pruned
		}
		counts[b.PreRestore]++
		if counts[b.PreRestore] <= keep {
			continue
		}
		if err := os.Remove(filepath.Join(dir, b.Name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return deleted, err
		}
		deleted = append(deleted, b.Name)
	}
	return deleted, nil
}
