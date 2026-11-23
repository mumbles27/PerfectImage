package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/cli"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// PassphraseEnv supplies the archive passphrase to the CLI.
const PassphraseEnv = "PERFECTIMAGE_BACKUP_PASSPHRASE"

func init() {
	cli.Register(cli.Command{Name: "backup", Summary: "Write an encrypted backup archive", Run: runBackupCmd})
	cli.Register(cli.Command{Name: "restore", Summary: "Restore from a backup archive (service must be stopped)", Run: runRestoreCmd})
}

func loadCLIConfig(path string) (*config.Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return config.Load(abs)
}

// readPassphrase reads the passphrase from a file (first line) or the
// environment. It never takes the passphrase from argv.
func readPassphrase(file string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		line, _, _ := strings.Cut(string(b), "\n")
		line = strings.TrimRight(line, "\r")
		if line == "" {
			return nil, errors.New("passphrase file is empty")
		}
		return []byte(line), nil
	}
	if v := os.Getenv(PassphraseEnv); v != "" {
		return []byte(v), nil
	}
	return nil, nil
}

// storedPassphrase reads the sealed passphrase from the database (same host).
func storedPassphrase(ctx context.Context, cfg *config.Config) ([]byte, error) {
	key, err := readMasterKey(KeyFile(cfg))
	if err != nil {
		return nil, err
	}
	sealer, err := secrets.NewAESGCM(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(ctx, cfg.Database.Path, store.Options{BusyTimeout: cfg.Database.BusyTimeout})
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ops := &Ops{db: db, sealer: sealer}
	return ops.Passphrase(ctx)
}

func runBackupCmd(ctx context.Context, env *cli.Env, args []string) error {
	fs, cfgPath := cli.FlagSet(env, "backup")
	out := fs.String("out", "", "output directory or .pibak file (default backup.dir)")
	passFile := fs.String("passphrase-file", "", "file containing the passphrase (default $"+PassphraseEnv+", then the stored passphrase)")
	noKey := fs.Bool("no-master-key", false, "do not include the host master key")
	if err := cli.ParseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadCLIConfig(*cfgPath)
	if err != nil {
		return err
	}
	pass, err := readPassphrase(*passFile)
	if err != nil {
		return err
	}
	if pass == nil {
		if pass, err = storedPassphrase(ctx, cfg); err != nil {
			return fmt.Errorf("no passphrase: use --passphrase-file or $%s (stored passphrase: %v)", PassphraseEnv, err)
		}
	}
	defer clear(pass)
	eng := &Engine{Cfg: cfg, AppVersion: env.Version, Passphrase: pass}
	if *noKey {
		f := false
		eng.IncludeMasterKey = &f
	}
	if eng.includeKey() {
		fmt.Fprintln(env.Stderr, "WARNING: the archive includes the host master key; protect the archive and its passphrase.")
	}
	p, err := eng.Backup(ctx, *out)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, p)
	return nil
}

// serviceRunning reports whether something accepts connections on the
// configured listen address.
func serviceRunning(cfg *config.Config) bool {
	host, port, err := net.SplitHostPort(cfg.Server.Listen)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func printManifest(w io.Writer, st *Staged) {
	m := st.Manifest
	fmt.Fprintf(w, "Archive created %s on %s by PerfectImage %s\n", m.CreatedAt.Format(time.RFC3339), m.Host, m.AppVersion)
	fmt.Fprintf(w, "Master key included: %v\n", m.IncludesMasterKey)
	for _, f := range m.Files {
		fmt.Fprintf(w, "  %-40s %10d  %s\n", f.Path, f.Size, f.SHA256[:16])
	}
	for _, warn := range st.Warnings {
		fmt.Fprintln(w, "WARNING:", warn)
	}
}

func runRestoreCmd(ctx context.Context, env *cli.Env, args []string) error {
	fs, cfgPath := cli.FlagSet(env, "restore")
	in := fs.String("in", "", "backup archive to restore (required)")
	passFile := fs.String("passphrase-file", "", "file containing the archive passphrase (default $"+PassphraseEnv+")")
	yes := fs.Bool("yes", false, "apply the restore (without it, only verify and show the manifest)")
	verifyOnly := fs.Bool("verify-only", false, "verify the archive and exit")
	force := fs.Bool("force", false, "restore a newer schema and skip the running-service check")
	noKey := fs.Bool("no-master-key", false, "do not install the archived master key")
	noCatalog := fs.Bool("no-catalog", false, "do not restore catalog directories")
	overwriteConfig := fs.Bool("overwrite-config", false, "replace the config file (default: write <config>.restored)")
	skipSafety := fs.Bool("skip-safety-backup", false, "do not back up the current state first")
	if err := cli.ParseFlags(fs, args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("%w: --in is required", cli.ErrUsage)
	}
	cfg, err := loadCLIConfig(*cfgPath)
	if err != nil {
		return err
	}
	pass, err := readPassphrase(*passFile)
	if err != nil {
		return err
	}
	if pass == nil {
		return fmt.Errorf("%w: provide the passphrase with --passphrase-file or $%s", cli.ErrUsage, PassphraseEnv)
	}
	defer clear(pass)
	eng := &Engine{Cfg: cfg, AppVersion: env.Version, Passphrase: pass}
	st, err := eng.Stage(ctx, *in, *force)
	if err != nil {
		return err
	}
	defer st.Cleanup()
	printManifest(env.Stdout, st)
	fmt.Fprintln(env.Stdout, "Archive verified.")
	if *verifyOnly || !*yes {
		if !*verifyOnly {
			fmt.Fprintln(env.Stdout, "Re-run with --yes to restore (stop the service first).")
		}
		return nil
	}
	if !*force && serviceRunning(cfg) {
		return fmt.Errorf("the service appears to be running on %s; stop it first (perfectimage stop)", cfg.Server.Listen)
	}
	opts := RestoreOptions{MasterKey: !*noKey, Catalog: !*noCatalog, OverwriteConfig: *overwriteConfig, SkipSafetyBackup: *skipSafety}
	res, err := eng.ApplyOffline(ctx, st, opts)
	if res != nil && res.SafetyBackup != "" {
		fmt.Fprintln(env.Stdout, "Safety backup of the previous state:", res.SafetyBackup)
	}
	if err != nil {
		return err
	}
	for _, r := range res.Restored {
		fmt.Fprintln(env.Stdout, "Restored:", r)
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(env.Stdout, "WARNING:", w)
	}
	if err := auditOffline(ctx, cfg, res, filepath.Base(*in)); err != nil {
		fmt.Fprintln(env.Stderr, "warning: could not record the restore in the audit log:", err)
	}
	fmt.Fprintln(env.Stdout, "Restore complete. Start the service: perfectimage start")
	return nil
}

// auditOffline appends a backup.restore event to the restored database's
// audit log (the service is stopped, so the CLI owns the hash chain).
func auditOffline(ctx context.Context, cfg *config.Config, res *Result, archive string) error {
	db, err := store.Open(ctx, cfg.Database.Path, store.Options{BusyTimeout: cfg.Database.BusyTimeout})
	if err != nil {
		return err
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'`).Scan(&n); err != nil || n == 0 {
		return err
	}
	st, err := auditlog.New(ctx, db, auditlog.Options{})
	if err != nil {
		return err
	}
	actor := "cli"
	if u, err := user.Current(); err == nil {
		actor = "cli:" + u.Username
	}
	details := map[string]any{"archive_version": res.Manifest.AppVersion, "archive_created": res.Manifest.CreatedAt,
		"restored": res.Restored, "warnings": len(res.Warnings), "via": "cli"}
	if res.SafetyBackup != "" {
		details["safety_backup"] = filepath.Base(res.SafetyBackup)
	}
	err = st.Record(ctx, audit.Event{Actor: actor, Action: "backup.restore", Target: "backup:" + archive,
		Outcome: audit.OutcomeSuccess, Details: details})
	cerr := st.Close(ctx)
	if err != nil {
		return err
	}
	return cerr
}
