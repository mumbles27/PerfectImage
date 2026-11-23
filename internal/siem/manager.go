package siem

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/logging"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// ErrUnknownOutput is returned for an output name that is not configured.
var ErrUnknownOutput = errors.New("siem: unknown output")

// Manager owns the configured outputs and fans records out to them.
type Manager struct {
	cfgs    []config.SIEMOutput
	outputs []*output
	byName  map[string]*output
	log     *slog.Logger
	host    string
	version string
	creds   Credentials
	minLog  slog.Level
	anyLogs bool
}

// Options configures NewManager.
type Options struct {
	Logger  *slog.Logger
	Version string
	Host    string // default os.Hostname()
}

// NewManager builds and starts every enabled output.
func NewManager(cfg config.SIEMConfig, creds Credentials, opts Options) (*Manager, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Host == "" {
		opts.Host, _ = os.Hostname()
	}
	m := &Manager{
		cfgs: cfg.Outputs, byName: map[string]*output{}, log: opts.Logger.With("component", "siem"),
		host: opts.Host, version: opts.Version, creds: creds, minLog: slog.LevelError + 1,
	}
	for _, c := range cfg.Outputs {
		if c.Disabled {
			continue
		}
		tr, err := newTransport(c, creds, opts.Version)
		if err != nil {
			m.closeAll(context.Background())
			return nil, fmt.Errorf("siem output %s: %w", c.Name, err)
		}
		o, err := newOutput(c, tr, cfg.SpillDir, m.log)
		if err != nil {
			_ = tr.Close()
			m.closeAll(context.Background())
			return nil, fmt.Errorf("siem output %s: %w", c.Name, err)
		}
		m.outputs = append(m.outputs, o)
		m.byName[c.Name] = o
		if o.logs {
			m.anyLogs = true
			m.minLog = min(m.minLog, o.minLevel)
		}
		o.start()
	}
	return m, nil
}

func newTransport(c config.SIEMOutput, creds Credentials, version string) (transport, error) {
	switch c.Type {
	case config.SIEMTypeSyslog, config.SIEMTypeCEF:
		return newSyslogTransport(c, version)
	case config.SIEMTypeSplunkHEC, config.SIEMTypeElastic, config.SIEMTypeWebhook:
		return newHTTPTransport(c, creds)
	case config.SIEMTypeFile:
		return newFileTransport(c)
	}
	return nil, fmt.Errorf("unknown type %q", c.Type)
}

// PublishAudit forwards persisted audit entries to outputs streaming audit
// events. It never blocks.
func (m *Manager) PublishAudit(entries []auditlog.Entry) {
	for _, e := range entries {
		r := FromAudit(e, m.host)
		for _, o := range m.outputs {
			if o.audit {
				o.enqueue(r)
			}
		}
	}
}

// PublishLog forwards an application log record. It never blocks.
func (m *Manager) PublishLog(r slog.Record) {
	if !m.anyLogs || r.Level < m.minLog {
		return
	}
	var rec *Record
	for _, o := range m.outputs {
		if o.logs && r.Level >= o.minLevel {
			if rec == nil {
				x := FromLog(r, m.host)
				rec = &x
			}
			o.enqueue(*rec)
		}
	}
}

// Test sends one synthetic event directly (bypassing the queue) to the named
// output and returns the delivery result.
func (m *Manager) Test(ctx context.Context, name, actor string) error {
	o, ok := m.byName[name]
	if !ok {
		return ErrUnknownOutput
	}
	r := Record{
		ID: randomID(), Kind: KindAudit, Time: time.Now().UTC(), Level: "info", Host: m.host,
		Message: "siem.test",
		Fields: map[string]any{"action": "siem.test", "outcome": "success", "actor": actor,
			"target": "siem:" + name, "details": map[string]any{"note": "PerfectImage SIEM test event"}},
	}
	ctx, cancel := context.WithTimeout(ctx, o.cfg.Timeout)
	defer cancel()
	err := o.tr.Send(ctx, []Record{r})
	if err != nil {
		o.failed.Add(1)
		o.statMu.Lock()
		o.lastErr, o.lastErrAt = err.Error(), o.now()
		o.statMu.Unlock()
		return err
	}
	o.sent.Add(1)
	o.statMu.Lock()
	o.lastOK = o.now()
	o.statMu.Unlock()
	return nil
}

// Statuses returns the health of every configured output (disabled ones
// included), in configuration order.
func (m *Manager) Statuses() []Status {
	out := make([]Status, 0, len(m.cfgs))
	for _, c := range m.cfgs {
		if o, ok := m.byName[c.Name]; ok {
			out = append(out, o.status())
			continue
		}
		out = append(out, Status{Name: c.Name, Type: c.Type, Target: target(c), Streams: c.Streams, MinLevel: c.MinLevel})
	}
	return out
}

// Output returns the configuration of the named output.
func (m *Manager) Output(name string) (config.SIEMOutput, bool) {
	i := slices.IndexFunc(m.cfgs, func(c config.SIEMOutput) bool { return c.Name == name })
	if i < 0 {
		return config.SIEMOutput{}, false
	}
	return m.cfgs[i], true
}

// Close flushes outputs (spilling undeliverable records) and stops them.
func (m *Manager) Close(ctx context.Context) error {
	return m.closeAll(ctx)
}

func (m *Manager) closeAll(ctx context.Context) error {
	var errs []error
	for _, o := range m.outputs {
		if err := o.close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// logSink adapts the Manager to logging.Sink.
type logSink struct{ m *Manager }

var _ logging.Sink = logSink{}

func (s logSink) Name() string { return "siem" }

func (s logSink) Enabled(l slog.Level) bool { return s.m.anyLogs && l >= s.m.minLog }

// Emit implements logging.Sink. Records logged by the siem component itself
// are skipped to avoid feedback loops.
func (s logSink) Emit(_ context.Context, r slog.Record) error {
	skip := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "component" && a.Value.String() == "siem" {
			skip = true
			return false
		}
		return true
	})
	if !skip {
		s.m.PublishLog(r)
	}
	return nil
}

func (s logSink) Close() error { return nil }

// dbCredentials stores output credentials sealed in siem_credentials.
type dbCredentials struct {
	db     *store.DB
	sealer secrets.Sealer
}

func credAAD(output, field string) string { return "siem:" + output + ":" + field }

// Get implements Credentials.
func (c *dbCredentials) Get(ctx context.Context, output, field string) (string, error) {
	var v string
	err := c.db.QueryRowContext(ctx, `SELECT value FROM siem_credentials WHERE output = ? AND field = ?`,
		output, field).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return secrets.DecryptString(c.sealer, v, credAAD(output, field))
}

// Set seals and stores a credential; an empty value deletes it.
func (c *dbCredentials) Set(ctx context.Context, output, field, value, by string) error {
	if value == "" {
		_, err := c.db.ExecContext(ctx, `DELETE FROM siem_credentials WHERE output = ? AND field = ?`, output, field)
		return err
	}
	sealed, err := secrets.EncryptString(c.sealer, value, credAAD(output, field))
	if err != nil {
		return err
	}
	_, err = c.db.ExecContext(ctx, `INSERT INTO siem_credentials (output, field, value, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT (output, field) DO UPDATE SET value = excluded.value,
		updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		output, field, sealed, time.Now().UTC().UnixMilli(), by)
	return err
}

// CredentialInfo describes whether a credential is set (never its value).
type CredentialInfo struct {
	Field     string
	Set       bool
	UpdatedAt time.Time
	UpdatedBy string
}

func (c *dbCredentials) Info(ctx context.Context, output string, fields []string) ([]CredentialInfo, error) {
	out := make([]CredentialInfo, 0, len(fields))
	for _, f := range fields {
		ci := CredentialInfo{Field: f}
		var ts int64
		err := c.db.QueryRowContext(ctx, `SELECT updated_at, updated_by FROM siem_credentials WHERE output = ? AND field = ?`,
			output, f).Scan(&ts, &ci.UpdatedBy)
		switch {
		case err == nil:
			ci.Set, ci.UpdatedAt = true, time.UnixMilli(ts)
		case !errors.Is(err, sql.ErrNoRows):
			return nil, err
		}
		out = append(out, ci)
	}
	return out, nil
}
