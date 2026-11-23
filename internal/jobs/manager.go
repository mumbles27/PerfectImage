package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mumbles27/PerfectImage/internal/store"
)

var (
	errCanceledByUser = errors.New("canceled by user")
	errShutdown       = errors.New("interrupted: service shutdown")
)

// Options configures a Manager.
type Options struct {
	Workers      int
	PollInterval time.Duration
	Logger       *slog.Logger
}

// Manager owns job handlers, the worker pool and the event hub.
type Manager struct {
	db   *store.DB
	opts Options
	log  *slog.Logger
	hub  *Hub
	wake chan struct{}

	mu       sync.Mutex
	handlers map[string]Handler
	running  map[string]context.CancelCauseFunc
	started  bool
	stop     context.CancelFunc
	wg       sync.WaitGroup
}

// New returns a Manager. The core migrations must have been applied to db.
func New(db *store.DB, opts Options) *Manager {
	if opts.Workers <= 0 {
		opts.Workers = 1
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	return &Manager{
		db:       db,
		opts:     opts,
		log:      opts.Logger.With("component", "jobs"),
		hub:      NewHub(),
		wake:     make(chan struct{}, 1),
		handlers: map[string]Handler{},
		running:  map[string]context.CancelCauseFunc{},
	}
}

// Register installs the handler for a job type. It must be called before
// Start; type names should be namespaced ("packer.build", "deploy.vm").
func (m *Manager) Register(typ string, h Handler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return ErrStarted
	}
	if typ == "" || h == nil {
		return errors.New("jobs: Register requires a type and handler")
	}
	if _, dup := m.handlers[typ]; dup {
		return fmt.Errorf("jobs: handler for %q already registered", typ)
	}
	m.handlers[typ] = h
	return nil
}

// Types returns the registered job types, sorted.
func (m *Manager) Types() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.handlers))
	for t := range m.handlers {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Hub returns the event hub.
func (m *Manager) Hub() *Hub { return m.hub }

// Subscribe is shorthand for Hub().Subscribe.
func (m *Manager) Subscribe(jobID string) (<-chan Event, func()) { return m.hub.Subscribe(jobID) }

// Start recovers jobs left running by a previous process (marking them
// failed) and starts the worker pool. Workers stop when ctx is canceled or
// Stop is called.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return ErrStarted
	}
	m.started = true
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	m.stop = cancel
	m.mu.Unlock()

	res, err := m.db.ExecContext(ctx,
		`UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE status = ?`,
		StatusFailed, "interrupted: service restarted while running", ms(time.Now()), StatusRunning)
	if err != nil {
		cancel()
		return fmt.Errorf("jobs: recover stale jobs: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		m.log.Warn("marked interrupted jobs as failed", "count", n)
	}

	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-runCtx.Done():
		}
	}()
	for i := 0; i < m.opts.Workers; i++ {
		m.wg.Add(1)
		go m.worker(runCtx, i)
	}
	m.log.Info("job workers started", "workers", m.opts.Workers, "types", m.Types())
	return nil
}

// Stop cancels running jobs and waits for workers to exit or ctx to expire.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	stop := m.stop
	m.mu.Unlock()
	if stop == nil {
		return nil
	}
	stop()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("jobs: workers did not stop: %w", ctx.Err())
	}
}

// Enqueue persists a new queued job. payload is marshaled to JSON (nil -> {}).
func (m *Manager) Enqueue(ctx context.Context, typ string, payload any, createdBy string) (string, error) {
	m.mu.Lock()
	_, ok := m.handlers[typ]
	m.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownType, typ)
	}
	raw := []byte("{}")
	if payload != nil {
		var err error
		if raw, err = json.Marshal(payload); err != nil {
			return "", fmt.Errorf("jobs: marshal payload: %w", err)
		}
	}
	id := newID()
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO jobs (id, type, status, payload, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, typ, StatusQueued, string(raw), createdBy, ms(time.Now())); err != nil {
		return "", fmt.Errorf("jobs: enqueue: %w", err)
	}
	m.hub.Publish(Event{Kind: EventStatus, JobID: id, Status: StatusQueued})
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return id, nil
}

// Cancel cancels a queued or running job.
func (m *Manager) Cancel(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	res, err := m.db.ExecContext(ctx,
		`UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE id = ? AND status = ?`,
		StatusCanceled, errCanceledByUser.Error(), ms(time.Now()), id, StatusQueued)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		m.hub.Publish(Event{Kind: EventStatus, JobID: id, Status: StatusCanceled})
		return nil
	}
	if cancel, ok := m.running[id]; ok {
		cancel(errCanceledByUser)
		return nil
	}
	if _, err := m.Get(ctx, id); err != nil {
		return err
	}
	return ErrNotCancelable
}

const jobCols = `id, type, status, payload, result, error, created_by, created_at, started_at, finished_at`

type scanner interface{ Scan(...any) error }

func scanJob(s scanner) (*Job, error) {
	var (
		j                 Job
		payload           string
		result, errStr    sql.NullString
		created           int64
		started, finished sql.NullInt64
	)
	if err := s.Scan(&j.ID, &j.Type, &j.Status, &payload, &result, &errStr, &j.CreatedBy, &created, &started, &finished); err != nil {
		return nil, err
	}
	j.Payload = json.RawMessage(payload)
	if result.Valid {
		j.Result = json.RawMessage(result.String)
	}
	j.Error = errStr.String
	j.CreatedAt = fromMS(created)
	if started.Valid {
		t := fromMS(started.Int64)
		j.StartedAt = &t
	}
	if finished.Valid {
		t := fromMS(finished.Int64)
		j.FinishedAt = &t
	}
	return &j, nil
}

// Get returns a job by ID.
func (m *Manager) Get(ctx context.Context, id string) (*Job, error) {
	j, err := scanJob(m.db.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}

// ListOptions filters List.
type ListOptions struct {
	Status Status
	Type   string
	Limit  int // default 50, max 500
	Offset int
}

// List returns jobs newest first.
func (m *Manager) List(ctx context.Context, o ListOptions) ([]*Job, error) {
	if o.Limit <= 0 {
		o.Limit = 50
	}
	if o.Limit > 500 {
		o.Limit = 500
	}
	var (
		where []string
		args  []any
	)
	if o.Status != "" {
		where = append(where, "status = ?")
		args = append(args, o.Status)
	}
	if o.Type != "" {
		where = append(where, "type = ?")
		args = append(args, o.Type)
	}
	q := `SELECT ` + jobCols + ` FROM jobs`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, o.Limit, o.Offset)
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Counts returns the number of jobs per status.
func (m *Manager) Counts(ctx context.Context) (map[Status]int, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT status, count(*) FROM jobs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Status]int{}
	for rows.Next() {
		var s Status
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// Logs returns up to limit log lines for a job with ID > afterID.
func (m *Manager) Logs(ctx context.Context, jobID string, afterID int64, limit int) ([]LogLine, error) {
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, ts, line FROM job_logs WHERE job_id = ? AND id > ? ORDER BY id LIMIT ?`,
		jobID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogLine
	for rows.Next() {
		l := LogLine{JobID: jobID}
		var ts int64
		if err := rows.Scan(&l.ID, &ts, &l.Line); err != nil {
			return nil, err
		}
		l.Time = fromMS(ts)
		out = append(out, l)
	}
	return out, rows.Err()
}

// AppendLog stores a log line for a job and publishes it.
func (m *Manager) AppendLog(ctx context.Context, jobID, line string) (LogLine, error) {
	now := time.Now().UTC()
	res, err := m.db.ExecContext(ctx, `INSERT INTO job_logs (job_id, ts, line) VALUES (?, ?, ?)`, jobID, ms(now), line)
	if err != nil {
		return LogLine{}, err
	}
	id, _ := res.LastInsertId()
	l := LogLine{ID: id, JobID: jobID, Time: now.Truncate(time.Millisecond), Line: line}
	m.hub.Publish(Event{Kind: EventLog, JobID: jobID, Line: &l})
	return l, nil
}

func (m *Manager) worker(ctx context.Context, n int) {
	defer m.wg.Done()
	t := time.NewTicker(m.opts.PollInterval)
	defer t.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		job, jobCtx, err := m.claim(ctx)
		if err != nil {
			if ctx.Err() == nil {
				m.log.Error("claim job", "worker", n, "err", err)
			}
		} else if job != nil {
			m.execute(ctx, jobCtx, job)
			continue // look for more work immediately
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-t.C:
		}
	}
}

// claim atomically moves the oldest queued job to running and registers its
// cancel func. Holding m.mu makes this atomic with respect to Cancel.
func (m *Manager) claim(ctx context.Context) (*Job, context.Context, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := m.db.QueryRowContext(ctx, `
		UPDATE jobs SET status = ?, started_at = ?
		WHERE id = (SELECT id FROM jobs WHERE status = ? ORDER BY created_at, id LIMIT 1)
		  AND status = ?
		RETURNING `+jobCols,
		StatusRunning, ms(time.Now()), StatusQueued, StatusQueued)
	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	jobCtx, cancel := context.WithCancelCause(ctx)
	m.running[job.ID] = cancel
	return job, jobCtx, nil
}

func (m *Manager) execute(workerCtx, ctx context.Context, job *Job) {
	m.hub.Publish(Event{Kind: EventStatus, JobID: job.ID, Status: StatusRunning})
	log := m.log.With("job_id", job.ID, "job_type", job.Type)
	log.Info("job started")

	m.mu.Lock()
	h := m.handlers[job.Type]
	m.mu.Unlock()

	lw := newLogWriter(m, job.ID)
	var (
		result any
		err    error
	)
	if h == nil {
		err = fmt.Errorf("%w: no handler registered for %q", ErrUnknownType, job.Type)
	} else {
		result, err = runHandler(ctx, log, h, job, lw)
	}
	lw.Flush()

	status, errMsg := StatusSucceeded, ""
	var resultJSON sql.NullString
	switch {
	case err == nil:
		if result != nil {
			b, mErr := json.Marshal(result)
			if mErr != nil {
				status, errMsg = StatusFailed, "marshal result: "+mErr.Error()
			} else {
				resultJSON = sql.NullString{String: string(b), Valid: true}
			}
		}
	case errors.Is(context.Cause(ctx), errCanceledByUser):
		status, errMsg = StatusCanceled, errCanceledByUser.Error()
	case workerCtx.Err() != nil:
		status, errMsg = StatusFailed, errShutdown.Error()
	default:
		status, errMsg = StatusFailed, err.Error()
	}

	m.mu.Lock()
	if cancel := m.running[job.ID]; cancel != nil {
		cancel(nil)
	}
	delete(m.running, job.ID)
	m.mu.Unlock()

	// The worker context may be canceled (shutdown); persist the outcome anyway.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(workerCtx), 10*time.Second)
	defer cancel()
	var errVal sql.NullString
	if errMsg != "" {
		errVal = sql.NullString{String: errMsg, Valid: true}
	}
	if _, dbErr := m.db.ExecContext(fctx,
		`UPDATE jobs SET status = ?, result = ?, error = ?, finished_at = ? WHERE id = ?`,
		status, resultJSON, errVal, ms(time.Now()), job.ID); dbErr != nil {
		log.Error("persist job outcome", "err", dbErr)
	}
	m.hub.Publish(Event{Kind: EventStatus, JobID: job.ID, Status: status})
	log.Info("job finished", "status", status, "error", errMsg)
}

func runHandler(ctx context.Context, log *slog.Logger, h Handler, job *Job, lw *LogWriter) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			lw.Printf("internal error: handler panicked (see service log)")
			log.Error("job handler panic", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		}
	}()
	return h.Run(ctx, job, lw)
}
