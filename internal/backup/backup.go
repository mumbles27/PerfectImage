// Package backup will implement consistent backup and restore of the data
// directory (SQLite online backup, sealed master key handling, catalog).
//
// Owner: ops agent. The foundation only defines the Service seam used by
// `perfectimage backup` / `perfectimage restore`.
package backup

import "context"

// Service performs backups and restores.
type Service interface {
	// Backup writes a backup archive to dest and returns its path.
	Backup(ctx context.Context, dest string) (string, error)
	// Restore restores from the archive at src. The service must be stopped.
	Restore(ctx context.Context, src string) error
}
