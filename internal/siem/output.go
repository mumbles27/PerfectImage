package siem

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/logging"
)

// transport delivers a batch to one destination. Send must honour ctx and
// return a *permanentError for failures that retrying cannot fix (the batch
// is then dropped).
type transport interface {
	Send(ctx context.Context, batch []Record) error
	Close() error
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return &permanentError{err} }

func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// Status is a point-in-time health snapshot of one output.
type Status struct {
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Target        string    `json:"target"`
	Enabled       bool      `json:"enabled"`
	Streams       []string  `json:"streams"`
	MinLevel      string    `json:"min_level"`
	Sent          uint64    `json:"sent"`
	Failed        uint64    `json:"failed"`  // failed delivery attempts
	Dropped       uint64    `json:"dropped"` // records lost (queue/spill full, rejected)
	Queued        int       `json:"queued"`
	QueueCap      int       `json:"queue_cap"`
	Spilled       int       `json:"spilled"` // records waiting in the backlog
	SpilledBytes  int64     `json:"spilled_bytes"`
	LastError     string    `json:"last_error,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitzero"`
	LastSuccessAt time.Time `json:"last_success_at,omitzero"`
	RetryAt       time.Time `json:"retry_at,omitzero"`
}

// Healthy reports whether the last delivery attempt succeeded.
func (s Status) Healthy() bool { return s.LastError == "" || s.LastSuccessAt.After(s.LastErrorAt) }

// baseBackoff is the first retry delay (a var so tests can shorten it).
var baseBackoff = 500 * time.Millisecond

type output struct {
	cfg      config.SIEMOutput
	tr       transport
	spill    *spill // nil: in-memory backlog only
	log      *slog.Logger
	minLevel slog.Level
	audit    bool
	logs     bool
	now      func() time.Time

	mu     sync.RWMutex // guards closed and sends on q
	closed bool
	q      chan Record
	done   chan struct{}

	mem []Record // in-memory backlog when spill is disabled

	sent, failed, dropped atomic.Uint64
	statMu                sync.Mutex
	lastErr               string
	lastErrAt, lastOK     time.Time
	retryAt               time.Time
	backoff               time.Duration
}

func newOutput(cfg config.SIEMOutput, tr transport, spillDir string, log *slog.Logger) (*output, error) {
	lvl, err := logging.ParseLevel(cfg.MinLevel)
	if err != nil {
		return nil, err
	}
	o := &output{
		cfg: cfg, tr: tr, log: log.With("output", cfg.Name), minLevel: lvl, now: time.Now,
		q: make(chan Record, cfg.QueueSize), done: make(chan struct{}),
	}
	for _, s := range cfg.Streams {
		o.audit = o.audit || s == "audit"
		o.logs = o.logs || s == "logs"
	}
	if cfg.SpillMaxMB > 0 {
		if o.spill, err = openSpill(spillDir, cfg.Name, int64(cfg.SpillMaxMB)<<20); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func (o *output) start() { go o.run() }

// enqueue never blocks: when the queue is full the record is dropped.
func (o *output) enqueue(r Record) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.closed {
		o.dropped.Add(1)
		return false
	}
	select {
	case o.q <- r:
		return true
	default:
		o.dropped.Add(1)
		return false
	}
}

// close stops intake and waits for the worker to flush or spill what is left.
func (o *output) close(ctx context.Context) error {
	o.mu.Lock()
	if !o.closed {
		o.closed = true
		close(o.q)
	}
	o.mu.Unlock()
	select {
	case <-o.done:
		return o.tr.Close()
	case <-ctx.Done():
		return fmt.Errorf("siem output %s: %w", o.cfg.Name, ctx.Err())
	}
}

func (o *output) run() {
	defer close(o.done)
	ticker := time.NewTicker(o.cfg.FlushInterval)
	defer ticker.Stop()
	var pending []Record
	retry := time.NewTimer(time.Hour)
	defer retry.Stop()
	for {
		var retryC <-chan time.Time
		if o.hasBacklog() {
			if wait := o.retryWait(); wait <= 0 {
				o.drainBacklog()
			}
			if o.hasBacklog() {
				retry.Reset(max(o.retryWait(), 10*time.Millisecond))
				retryC = retry.C
			}
		}
		select {
		case r, ok := <-o.q:
			if !ok {
				o.shutdown(pending)
				return
			}
			pending = append(pending, r)
			if len(pending) >= o.cfg.BatchSize {
				o.flush(pending)
				pending = nil
			}
		case <-ticker.C:
			if len(pending) > 0 {
				o.flush(pending)
				pending = nil
			}
		case <-retryC:
		}
	}
}

func (o *output) retryWait() time.Duration {
	o.statMu.Lock()
	defer o.statMu.Unlock()
	return o.retryAt.Sub(o.now())
}

func (o *output) hasBacklog() bool {
	if len(o.mem) > 0 {
		return true
	}
	if o.spill != nil {
		n, _ := o.spill.Pending()
		return n > 0
	}
	return false
}

func (o *output) send(batch []Record) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.cfg.Timeout)
	defer cancel()
	return o.tr.Send(ctx, batch)
}

// flush delivers a fresh batch, keeping order behind any backlog.
func (o *output) flush(batch []Record) {
	if o.hasBacklog() || o.retryWait() > 0 {
		o.toBacklog(batch)
		return
	}
	if err := o.send(batch); err != nil {
		if o.failure(err, len(batch)) {
			o.toBacklog(batch)
		}
		return
	}
	o.success(len(batch))
}

// drainBacklog sends backlog batches (oldest first) until empty or failing.
func (o *output) drainBacklog() {
	for o.hasBacklog() {
		if len(o.mem) > 0 {
			n := min(len(o.mem), o.cfg.BatchSize)
			batch := o.mem[:n]
			if err := o.send(batch); err != nil {
				if o.failure(err, n) {
					return
				}
			} else {
				o.success(n)
			}
			o.mem = o.mem[n:]
			continue
		}
		batch, off, err := o.spill.Peek(o.cfg.BatchSize)
		if err != nil {
			o.recordErr(fmt.Errorf("read spill: %w", err))
			o.setRetry()
			return
		}
		if len(batch) > 0 {
			if err := o.send(batch); err != nil {
				if o.failure(err, len(batch)) {
					return
				}
			} else {
				o.success(len(batch))
			}
		}
		if err := o.spill.Commit(off, len(batch)); err != nil {
			o.recordErr(fmt.Errorf("commit spill: %w", err))
			o.setRetry()
			return
		}
	}
}

// toBacklog parks records in the spill file (or memory). Records that do
// not fit are dropped and counted.
func (o *output) toBacklog(batch []Record) {
	if o.spill != nil {
		if err := o.spill.Append(batch); err != nil {
			o.dropped.Add(uint64(len(batch)))
			o.recordErr(fmt.Errorf("spill: %w", err))
		}
		return
	}
	room := o.cfg.QueueSize - len(o.mem)
	if room < len(batch) {
		o.dropped.Add(uint64(len(batch) - max(room, 0)))
		batch = batch[:max(room, 0)]
	}
	o.mem = append(o.mem, batch...)
}

// failure records a failed attempt. It reports whether the batch should be
// retried (false for permanent errors, whose records are dropped).
func (o *output) failure(err error, n int) bool {
	o.failed.Add(1)
	o.recordErr(err)
	if isPermanent(err) {
		o.dropped.Add(uint64(n))
		return false
	}
	o.setRetry()
	return true
}

func (o *output) recordErr(err error) {
	o.statMu.Lock()
	o.lastErr, o.lastErrAt = err.Error(), o.now()
	o.statMu.Unlock()
	// o.log carries component=siem, so the log sink does not forward this
	// record (no feedback loop).
	o.log.Warn("siem delivery failed", "err", err)
}

// setRetry schedules the next attempt with exponential backoff and jitter.
func (o *output) setRetry() {
	o.statMu.Lock()
	defer o.statMu.Unlock()
	if o.backoff == 0 {
		o.backoff = baseBackoff
	} else {
		o.backoff = min(o.backoff*2, o.cfg.MaxBackoff)
	}
	jitter := time.Duration(rand.Int64N(int64(o.backoff)/5 + 1))
	o.retryAt = o.now().Add(o.backoff + jitter)
}

func (o *output) success(n int) {
	o.sent.Add(uint64(n))
	o.statMu.Lock()
	o.lastOK, o.backoff, o.retryAt = o.now(), 0, time.Time{}
	o.statMu.Unlock()
}

// shutdown makes one last delivery attempt; anything undeliverable is
// spilled to disk for the next start.
func (o *output) shutdown(pending []Record) {
	if o.retryWait() <= 0 && o.hasBacklog() {
		o.drainBacklog()
	}
	if len(pending) > 0 {
		o.flush(pending)
	}
	if n := len(o.mem); n > 0 {
		o.dropped.Add(uint64(n))
		o.mem = nil
	}
}

func (o *output) status() Status {
	st := Status{
		Name: o.cfg.Name, Type: o.cfg.Type, Target: target(o.cfg), Enabled: true,
		Streams: o.cfg.Streams, MinLevel: o.cfg.MinLevel,
		Sent: o.sent.Load(), Failed: o.failed.Load(), Dropped: o.dropped.Load(),
		Queued: len(o.q), QueueCap: cap(o.q),
	}
	if o.spill != nil {
		st.Spilled, st.SpilledBytes = o.spill.Pending()
	}
	o.statMu.Lock()
	st.LastError, st.LastErrorAt, st.LastSuccessAt, st.RetryAt = o.lastErr, o.lastErrAt, o.lastOK, o.retryAt
	o.statMu.Unlock()
	return st
}

func target(c config.SIEMOutput) string {
	switch c.Type {
	case config.SIEMTypeSyslog, config.SIEMTypeCEF:
		return c.Address
	case config.SIEMTypeFile:
		return c.Path
	default:
		return c.URL
	}
}
