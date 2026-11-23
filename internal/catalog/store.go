package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	catalogdata "github.com/mumbles27/PerfectImage/catalog"
)

// EmbeddedFS returns the built-in catalog (the repository's catalog/ tree).
func EmbeddedFS() fs.FS { return catalogdata.FS }

func dirFS(dir string) fs.FS { return os.DirFS(dir) }

// Store holds the current catalog snapshot and reloads it when files in the
// override directories change. It is safe for concurrent use.
type Store struct {
	embedded fs.FS
	dirs     []string
	log      *slog.Logger

	cur atomic.Pointer[Catalog]

	mu          sync.Mutex // serializes reloads and writes
	fingerprint string
	loadedAt    time.Time
}

// NewStore creates a store over the embedded catalog (may be nil) and the
// override directories, later directories winning. Call Reload before use.
func NewStore(embedded fs.FS, dirs []string, log *slog.Logger) *Store {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Store{embedded: embedded, dirs: append([]string(nil), dirs...), log: log}
	s.cur.Store(&Catalog{Images: map[string]*Image{}, Apps: map[string]*App{}, Bundles: map[string]*Bundle{}})
	return s
}

// Catalog returns the current snapshot. Never nil.
func (s *Store) Catalog() *Catalog { return s.cur.Load() }

// Dirs returns the override directories in merge order.
func (s *Store) Dirs() []string { return append([]string(nil), s.dirs...) }

// WriteDir is the override directory the editor writes to: the last (highest
// precedence) configured directory. Empty when none is configured.
func (s *Store) WriteDir() string {
	if len(s.dirs) == 0 {
		return ""
	}
	return s.dirs[len(s.dirs)-1]
}

// LoadedAt returns when the current snapshot was loaded.
func (s *Store) LoadedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadedAt
}

func (s *Store) layers() []Layer {
	var ls []Layer
	if s.embedded != nil {
		ls = append(ls, Layer{Origin: OriginEmbedded, FS: s.embedded})
	}
	for _, d := range s.dirs {
		ls = append(ls, DirLayer(d))
	}
	return ls
}

// Reload loads the catalog if the override directories changed since the
// last load (or force is set). It reports whether a new snapshot was
// installed.
func (s *Store) Reload(ctx context.Context, force bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked(ctx, force)
}

func (s *Store) reloadLocked(ctx context.Context, force bool) (bool, error) {
	fp, err := fingerprint(s.dirs)
	if err != nil {
		return false, err
	}
	if !force && fp == s.fingerprint {
		return false, nil
	}
	c, err := Load(ctx, s.layers()...)
	if err != nil {
		return false, err
	}
	s.cur.Store(c)
	s.fingerprint = fp
	s.loadedAt = time.Now()
	s.log.Info("catalog loaded", "images", len(c.Images), "apps", len(c.Apps),
		"bundles", len(c.Bundles), "problems", len(c.Problems))
	for _, p := range c.Problems {
		s.log.Warn("catalog problem", "problem", p.String())
	}
	return true, nil
}

// Watch polls the override directories every interval and reloads on
// change until ctx is canceled.
func (s *Store) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Reload(ctx, false); err != nil && ctx.Err() == nil {
				s.log.Error("catalog reload", "err", err)
			}
		}
	}
}

// fingerprint hashes path, size and mtime of every file in dirs.
func fingerprint(dirs []string) (string, error) {
	h := sha256.New()
	for _, d := range dirs {
		fmt.Fprintf(h, "dir %s\n", d)
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			info, err := e.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			fmt.Fprintf(h, "%s %d %d %v\n", p, info.Size(), info.ModTime().UnixNano(), e.IsDir())
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var (
	sharedMu    sync.Mutex
	sharedStore *Store
)

// Shared returns the process-wide store, creating it on first use from the
// embedded catalog plus dirs. The catalog and packer plugins share it.
func Shared(dirs []string, log *slog.Logger) *Store {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedStore == nil {
		sharedStore = NewStore(EmbeddedFS(), dirs, log)
	}
	return sharedStore
}

// ErrNotInitialized is returned by Resolve before the catalog plugin has
// initialized the shared store.
var ErrNotInitialized = errors.New("catalog: not initialized")

// Resolve resolves app/bundle ids against the shared store's current
// catalog. It is the entry point for the deploy package's adapter.
func Resolve(os OSFamily, distroFamily string, appIDs []string) ([]InstallStep, error) {
	sharedMu.Lock()
	s := sharedStore
	sharedMu.Unlock()
	if s == nil {
		return nil, ErrNotInitialized
	}
	return s.Catalog().Resolve(os, distroFamily, appIDs)
}
