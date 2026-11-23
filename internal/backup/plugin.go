package backup

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

// JobType is the scheduled/manual backup job.
const JobType = "backup.run"

// Settings key holding the sealed backup passphrase.
const (
	passphraseKey = "backup.passphrase"
	passphraseAAD = "backup:passphrase"
	// MinPassphraseLen is enforced for stored passphrases.
	MinPassphraseLen = 12
)

// ErrNoPassphrase is returned when no backup passphrase has been stored.
var ErrNoPassphrase = errors.New("backup passphrase not configured (set it on /settings/backup)")

func init() {
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "backup" }

func (plugin) Init(_ context.Context, d *app.Deps) error {
	svc := &Ops{
		cfg: d.Config, db: d.DB, sealer: d.Sealer, jobs: d.Jobs, audit: d.Audit,
		log: d.Logger.With("component", "backup"), version: buildVersion(), auditStore: auditlog.For(d),
	}
	var sched cron.Schedule
	if spec := d.Config.Backup.Schedule; spec != "" {
		var err error
		if sched, err = cron.ParseStandard(spec); err != nil {
			return fmt.Errorf("backup.schedule %q: %w", spec, err)
		}
	}
	if err := d.Jobs.Register(JobType, svc); err != nil {
		return err
	}
	d.Web.AddModule(&module{svc: svc})
	d.Web.AddReadinessCheck("backup", func(context.Context) error {
		if r := svc.RestartRequired(); r != "" {
			return errors.New(r)
		}
		return nil
	})
	if sched != nil {
		d.Go(func(ctx context.Context) { svc.scheduleLoop(ctx, sched) })
	}
	return nil
}

// Ops is the in-service backup component: scheduled/manual backup jobs,
// stored passphrase and online restore.
type Ops struct {
	cfg        *config.Config
	db         *store.DB
	sealer     secrets.Sealer
	jobs       *jobs.Manager
	audit      audit.Recorder
	auditStore *auditlog.Store
	log        *slog.Logger
	version    string
	now        func() time.Time
	kdf        KDFParams // zero: DefaultKDF (tests lower it)

	mu              sync.Mutex // serializes backups and restores
	restartRequired string
}

func (s *Ops) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// RestartRequired returns a non-empty reason after an online restore.
func (s *Ops) RestartRequired() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restartRequired
}

// Passphrase returns the stored backup passphrase.
func (s *Ops) Passphrase(ctx context.Context) ([]byte, error) {
	v, err := s.db.GetSetting(ctx, passphraseKey)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoPassphrase
	}
	if err != nil {
		return nil, err
	}
	p, err := secrets.DecryptString(s.sealer, v, passphraseAAD)
	if err != nil {
		return nil, fmt.Errorf("unseal backup passphrase: %w", err)
	}
	return []byte(p), nil
}

// HasPassphrase reports whether a passphrase is stored.
func (s *Ops) HasPassphrase(ctx context.Context) bool {
	_, err := s.db.GetSetting(ctx, passphraseKey)
	return err == nil
}

// SetPassphrase seals and stores the backup passphrase.
func (s *Ops) SetPassphrase(ctx context.Context, p string) error {
	if len(p) < MinPassphraseLen {
		return fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLen)
	}
	v, err := secrets.EncryptString(s.sealer, p, passphraseAAD)
	if err != nil {
		return err
	}
	return s.db.SetSetting(ctx, passphraseKey, v)
}

func (s *Ops) engine(pass []byte) *Engine {
	return &Engine{Cfg: s.cfg, AppVersion: s.version, Passphrase: pass, Logger: s.log, LiveDB: s.db, KDF: s.kdf}
}

// RunResult is the backup.run job result.
type RunResult struct {
	File   string   `json:"file"`
	Size   int64    `json:"size"`
	CopyTo string   `json:"copy_to,omitempty"`
	Pruned []string `json:"pruned,omitempty"`
}

type runPayload struct {
	Trigger string `json:"trigger"` // manual | schedule
}

// Run implements jobs.Handler for backup.run.
func (s *Ops) Run(ctx context.Context, job *jobs.Job, lw *jobs.LogWriter) (any, error) {
	var p runPayload
	_ = job.DecodePayload(&p)
	actor := job.CreatedBy
	if actor == "" {
		actor = "system"
	}
	ev := audit.Event{Actor: actor, Action: "backup.run", Target: "job:" + job.ID, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"trigger": p.Trigger}}
	res, err := s.runBackup(ctx, lw)
	if err != nil {
		ev.Outcome, ev.Reason = audit.OutcomeFailure, err.Error()
		_ = s.audit.Record(ctx, ev)
		return nil, err
	}
	ev.Target = "backup:" + filepath.Base(res.File)
	ev.Details["size"] = res.Size
	ev.Details["pruned"] = len(res.Pruned)
	if res.CopyTo != "" {
		ev.Details["copy_to"] = res.CopyTo
	}
	_ = s.audit.Record(ctx, ev)
	return res, nil
}

func (s *Ops) runBackup(ctx context.Context, lw *jobs.LogWriter) (*RunResult, error) {
	if r := s.RestartRequired(); r != "" {
		return nil, errors.New(r)
	}
	pass, err := s.Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	s.mu.Lock()
	defer s.mu.Unlock()
	lw.Printf("writing backup to %s", s.cfg.Backup.Dir)
	if s.cfg.Backup.MasterKeyIncluded() {
		lw.Printf("WARNING: the archive includes the host master key (protected only by the backup passphrase)")
	}
	out, err := s.engine(pass).Backup(ctx, s.cfg.Backup.Dir)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(out)
	if err != nil {
		return nil, err
	}
	res := &RunResult{File: out, Size: fi.Size()}
	lw.Printf("wrote %s (%d bytes)", filepath.Base(out), fi.Size())
	if dst := s.cfg.Backup.CopyTo; dst != "" {
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return res, fmt.Errorf("copy_to: %w", err)
		}
		target := filepath.Join(dst, filepath.Base(out))
		if err := copyFile(out, target); err != nil {
			return res, fmt.Errorf("copy_to: %w", err)
		}
		res.CopyTo = target
		lw.Printf("copied to %s", target)
		pruned, err := Prune(dst, s.cfg.Backup.Retention)
		if err != nil {
			return res, fmt.Errorf("prune copy_to: %w", err)
		}
		res.Pruned = append(res.Pruned, pruned...)
	}
	pruned, err := Prune(s.cfg.Backup.Dir, s.cfg.Backup.Retention)
	if err != nil {
		return res, fmt.Errorf("prune: %w", err)
	}
	res.Pruned = append(res.Pruned, pruned...)
	for _, n := range res.Pruned {
		lw.Printf("pruned %s (retention %d)", n, s.cfg.Backup.Retention)
	}
	return res, nil
}

func (s *Ops) scheduleLoop(ctx context.Context, sched cron.Schedule) {
	for {
		next := sched.Next(s.clock())
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if _, err := s.jobs.Enqueue(ctx, JobType, runPayload{Trigger: "schedule"}, "system"); err != nil {
			s.log.Error("enqueue scheduled backup", "err", err)
		}
	}
}

// RestoreUpload stages and applies an uploaded archive to the running
// service. Job workers are stopped first; afterwards the service must be
// restarted.
func (s *Ops) RestoreUpload(ctx context.Context, archive string, pass []byte, force bool) (*Result, error) {
	if !s.mu.TryLock() {
		return nil, errors.New("a backup or restore is already running")
	}
	defer s.mu.Unlock()
	if s.restartRequired != "" {
		return nil, errors.New(s.restartRequired)
	}
	eng := s.engine(pass)
	st, err := eng.Stage(ctx, archive, force)
	if err != nil {
		return nil, err
	}
	defer st.Cleanup()
	counts, err := s.jobs.Counts(ctx)
	if err != nil {
		return nil, err
	}
	if n := counts[jobs.StatusRunning]; n > 0 && !force {
		return nil, fmt.Errorf("%d job(s) are running; wait for them or force the restore (they will be interrupted)", n)
	}
	// Stop job intake: no worker claims or runs jobs from here on.
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = s.jobs.Stop(stopCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("stop job workers: %w", err)
	}
	s.restartRequired = "restart required: the database was restored"
	if s.auditStore != nil {
		// Persist everything recorded so far into the pre-restore database
		// (it is captured by the safety backup).
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = s.auditStore.Flush(fctx)
		cancel()
	}
	res, err := eng.ApplyLive(ctx, st, DefaultRestoreOptions)
	if s.auditStore != nil {
		if rerr := s.auditStore.Reload(context.WithoutCancel(ctx)); rerr != nil {
			s.log.Error("reload audit chain head after restore", "err", rerr)
		}
	}
	if err != nil && res == nil {
		// The database swap did not happen; the old state is intact.
		s.restartRequired = "restart required: job workers were stopped for a restore that failed"
	}
	return res, err
}

// buildVersion returns the module version or VCS revision of the binary.
func buildVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return "dev-" + s.Value[:12]
		}
	}
	return "dev"
}
