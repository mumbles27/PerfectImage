# Backup and restore

## What is in an archive

A backup is a single `*.pibak` file (mode 0600). It contains a tar.gz stream
with these entries:

| entry | content |
|---|---|
| `perfectimage.db` | consistent SQLite snapshot (`VACUUM INTO`, safe while the service runs) |
| `config.yaml` | the config file the service or CLI was started with |
| `catalog/<i>/…` | regular files of each `catalog.dirs[i]` |
| `secrets/master.key` | raw 32-byte host master key (only if `backup.include_master_key`) |
| `manifest.json` | format, app version, host, creation time, per-namespace schema versions, catalog dirs, size and SHA-256 of every file |

### Encryption

- **Key derivation.** The passphrase goes through argon2id (t=3, 64 MiB, p=4;
  the parameters are stored in the header), which yields an AES-256 key and an
  HMAC key.
- **Header check.** The header ends with an HMAC that tells a wrong
  passphrase apart from a damaged body.
- **Chunks.** The stream is encrypted with AES-256-GCM in 64 KiB chunks.
  - Each chunk nonce is a random prefix, the chunk index and a final flag.
  - The header is the AAD of every chunk.
  - Any modification, reordering, truncation or trailing data fails
    authentication.
  - Archives of any size are processed in constant memory.

### Master key (default on)

Credentials in the database (Proxmox tokens, SIEM keys, the backup passphrase)
are sealed with the host master key. That key lives in
`secrets/master.key`, or in a DPAPI blob on Windows. Without it, a database
restored on a new host cannot decrypt those credentials. The archive therefore
includes the key by default, protected by the backup passphrase.

> **Warning:** anyone who has an archive **and** its passphrase can decrypt
> every stored credential. Use a long, unique passphrase, store it offline
> (it is needed to restore), and protect archive copies like the credentials
> themselves. To exclude the key, set `backup.include_master_key: false` or
> pass `perfectimage backup --no-master-key`. You will then have to re-enter
> credentials after restoring on a different host.

On restore, a different existing key is renamed to
`master.key.pre-restore-<ts>` and replaced. On Windows the restored key is
re-protected with DPAPI (machine scope).

## Configuration

```yaml
backup:
  dir: ""                 # default <data_dir>/backups
  retention: 7            # newest scheduled archives kept, and newest pre-restore archives kept
  schedule: "0 2 * * *"   # 5-field cron or @daily/@hourly/@every 6h; empty = manual only
  copy_to: '\\nas\backups\perfectimage'   # optional second dir / UNC path
  include_master_key: true
  max_upload_mb: 2048
```

- **Schedule.** The schedule uses the service's local time zone. An invalid
  expression stops the service from starting.
- **Jobs.** Each run, scheduled or *Run backup now*, is a `backup.run` job
  with a live log. It is audited as `backup.run`, with the actor set to the
  user or `system`.
- **Retention.** After each run, retention prunes `perfectimage-*.pibak` and
  `pre-restore-*.pibak` separately in `dir` and in `copy_to`. Manually named
  archives are never pruned.
- **Passphrase.** Scheduled and UI backups use the passphrase stored (sealed)
  on `/settings/backup`. It must be at least 12 characters and requires
  `settings.manage`.

## Web UI (`/settings/backup`)

- **List, run now and download** need `backup.run`. Downloads are audited
  (`backup.download`) and refused if the audit log is unavailable.
- **Restore by upload** needs `settings.manage` **and** `backup.run`. You must
  type `RESTORE` to confirm. If the passphrase field is blank, the stored
  passphrase is used. Steps:
  1. Stream the upload to a temp file and verify it fully (see below). Nothing
     changes if verification fails.
  2. Refuse if jobs are running, unless *Force* is checked.
  3. Stop the job workers (job intake).
  4. Write a safety backup (`pre-restore-*.pibak`) of the live database.
  5. Swap the database atomically with the SQLite online backup API. All pages
     are copied in one write transaction while the service keeps its
     connections.
  6. Install the master key and catalog dirs. The archived config is written to
     `<config>.restored` for review.
  7. Record `backup.restore` in the restored database's audit chain.
  8. `/readyz` reports `backup: restart required` until you **restart the
     service**. In-memory state is stale, and job processing stays stopped.

  Large uploads may hit the server's 60 s read timeout. Use the CLI for big
  archives.

## CLI

The passphrase is never taken from argv. Use `--passphrase-file <file>` (first
line) or `$PERFECTIMAGE_BACKUP_PASSPHRASE`. `backup` also falls back to the
stored passphrase.

```sh
# Works while the service runs.
perfectimage backup --config /etc/perfectimage/config.yaml [--out DIR|FILE.pibak] [--no-master-key]

# Verify only (default without --yes): decrypts, checks hashes, integrity and schema, prints the manifest.
perfectimage restore --config … --in backup.pibak --passphrase-file pass.txt

# Apply (service must be stopped).
perfectimage stop
perfectimage restore --config … --in backup.pibak --passphrase-file pass.txt --yes
perfectimage start
```

Restore flags:

| flag | effect |
|---|---|
| `--force` | restore a newer schema, and skip the running-service check |
| `--no-master-key` | keep the current key |
| `--no-catalog` | keep the current catalog dirs |
| `--overwrite-config` | replace the config file; the old one is kept as `.pre-restore-<ts>` |
| `--skip-safety-backup` | skip the pre-restore safety backup |

The CLI refuses to apply while something listens on `server.listen`. It takes
the safety backup, removes stale `-wal`/`-shm` files, renames the snapshot over
the database, restores the key and catalog, then appends `backup.restore`
(actor `cli:<os user>`) to the restored audit chain.

## Verification on restore

1. **Header.** The header HMAC must match; otherwise the error is "wrong
   passphrase".
2. **Encryption.** Every chunk must authenticate, and the stream must end
   with the final chunk; otherwise the error is "corrupted or tampered".
3. **Tar entries.** Entries must be regular files with safe relative names
   from the known set (no `..`, absolute or drive paths). The total size is
   capped. The manifest must be the last entry.
4. **Manifest.** Every file must match the manifest's size and SHA-256, with
   no extra or missing files.
5. **Snapshot.** The snapshot must pass `PRAGMA integrity_check`, and its
   schema versions must equal the manifest's.
6. **Version.** A schema version newer than the current database's is
   refused unless forced. A different app version is a warning. Migrations
   run on the next start.

Staging happens in a private directory next to the database, so the final
rename stays on the same filesystem. The directory is removed afterwards.
