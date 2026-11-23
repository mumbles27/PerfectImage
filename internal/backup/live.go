package backup

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"modernc.org/sqlite"
)

type restorer interface {
	NewRestore(srcURI string) (*sqlite.Backup, error)
}

// ApplyLive restores a staged archive into the running service's database
// using the SQLite online backup API: all pages are copied inside one write
// transaction, so other connections see either the old or the new database.
// The caller must stop job intake first and restart the service afterwards
// (in-memory state such as caches and the audit chain head is stale).
func (e *Engine) ApplyLive(ctx context.Context, st *Staged, opts RestoreOptions) (*Result, error) {
	if e.LiveDB == nil {
		return nil, errors.New("backup: ApplyLive requires the live database")
	}
	res := &Result{Manifest: st.Manifest, Warnings: append([]string(nil), st.Warnings...)}
	if !opts.SkipSafetyBackup {
		p, err := e.SafetyBackup(ctx)
		if err != nil {
			return nil, err
		}
		res.SafetyBackup = p
	}
	conn, err := e.LiveDB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	src := filepath.ToSlash(st.DBPath())
	err = conn.Raw(func(dc any) error {
		r, ok := dc.(restorer)
		if !ok {
			return errors.New("backup: database driver does not support online restore")
		}
		for attempt := 0; ; attempt++ {
			err := restoreOnce(r, src)
			if err == nil || attempt >= 50 || !isBusy(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("swap database: %w", err)
	}
	res.Restored = append(res.Restored, "database")
	if err := e.applyFiles(st, opts, res); err != nil {
		return res, err
	}
	return res, nil
}

func restoreOnce(r restorer, src string) error {
	b, err := r.NewRestore(src)
	if err != nil {
		return err
	}
	for {
		more, err := b.Step(-1)
		if err != nil {
			_ = b.Finish()
			return err
		}
		if !more {
			return b.Finish()
		}
	}
}

func isBusy(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "busy") || strings.Contains(s, "locked")
}
