// Package backup implements encrypted backup and restore of a PerfectImage
// installation.
//
// An archive (*.pibak) is a tar.gz stream containing a VACUUM INTO snapshot
// of the SQLite database, the config file, the catalog directories, the
// host master key (optional, default on) and a manifest (app version,
// schema versions, timestamp, SHA-256 of every file). The stream is
// encrypted with AES-256-GCM in 64 KiB chunks under a key derived from a
// passphrase with argon2id (see crypt.go for the format).
//
// Restore verifies the passphrase, every chunk, the manifest hashes, the
// SQLite integrity and the schema versions before touching anything, then
// writes a pre-restore safety backup and swaps the database atomically:
// by rename while the service is stopped (CLI) or with the SQLite online
// backup API from the web UI (job workers are stopped first and the service
// must be restarted afterwards).
//
// The plugin registers the "backup.run" job (manual and scheduled via
// backup.schedule), the /settings/backup page and the `backup` / `restore`
// CLI commands. See docs/backup.md.
package backup

import "context"

// Service performs backups and restores.
type Service interface {
	// Backup writes a backup archive to dest and returns its path.
	Backup(ctx context.Context, dest string) (string, error)
	// Restore restores from the archive at src. The service must be stopped.
	Restore(ctx context.Context, src string) error
}
