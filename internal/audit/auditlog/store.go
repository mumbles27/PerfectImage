// Package auditlog is the persistent, hash-chained audit log: an
// audit.Recorder backed by the append-only audit_events table, retention,
// chain verification, query/export and the /audit UI.
//
// Recording is asynchronous: Record validates and enqueues the event in a
// bounded buffer and returns immediately. A single writer goroutine batches
// events into transactions, extends the SHA-256 hash chain and then notifies
// subscribers (e.g. SIEM forwarders) with the persisted entries.
//
// The plugin installs the Store with Deps.Audit.Set. Other ops packages find
// it with For(deps).
package auditlog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// Errors.
var (
	ErrQueueFull = errors.New("audit: queue full, event dropped")
	ErrClosed    = errors.New("audit: recorder closed")
)

// Options configures a Store.
type Options struct {
	// QueueSize bounds the in-memory buffer (default 4096).
	QueueSize int
	// BatchSize is the maximum number of events per transaction (default 256).
	BatchSize int
	// FullWait is how long Record waits for room in a full queue before
	// dropping the event (default 100ms).
	FullWait time.Duration
	Logger   *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Metrics are recorder health counters.
type Metrics struct {
	Enqueued    uint64    `json:"enqueued"`
	Recorded    uint64    `json:"recorded"`
	Dropped     uint64    `json:"dropped"`
	WriteErrors uint64    `json:"write_errors"`
	Pruned      uint64    `json:"pruned"`
	QueueLen    int       `json:"queue_len"`
	QueueCap    int       `json:"queue_cap"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	LastWriteAt time.Time `json:"last_write_at,omitzero"`
}

type item struct {
	ev   audit.Event
	done chan struct{} // flush marker when non-nil
}

// Store is the persistent audit recorder.
type Store struct {
	db   *store.DB
	opts Options
	log  *slog.Logger

	mu     sync.RWMutex // guards closed and sends on q
	closed bool
	q      chan item
	done   chan struct{}

	headMu sync.Mutex
	head   string // hash of the newest event

	subMu  sync.RWMutex
	subs   map[int]func([]Entry)
	nextID int

	enqueued, recorded, dropped, writeErrs, pruned atomic.Uint64
	statMu                                         sync.Mutex
	lastErr                                        string
	lastErrAt, lastWriteAt                         time.Time
}

var _ audit.Recorder = (*Store)(nil)

// New opens the store (the "audit" migrations must be applied) and starts
// the writer goroutine. Call Close to drain the queue.
func New(ctx context.Context, db *store.DB, opts Options) (*Store, error) {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 4096
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 256
	}
	if opts.FullWait <= 0 {
		opts.FullWait = 100 * time.Millisecond
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Store{
		db:   db,
		opts: opts,
		log:  opts.Logger.With("component", "audit"),
		q:    make(chan item, opts.QueueSize),
		done: make(chan struct{}),
		subs: map[int]func([]Entry){},
	}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	go s.writer()
	return s, nil
}

func (s *Store) now() time.Time { return s.opts.Now().UTC() }

// Reload re-reads the chain head from the database. Call it after the
// database content was replaced underneath the store (online restore).
func (s *Store) Reload(ctx context.Context) error {
	var head string
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		err = s.db.QueryRowContext(ctx, `SELECT anchor_hash FROM audit_chain WHERE id = 1`).Scan(&head)
	}
	if err != nil {
		return fmt.Errorf("audit: load chain head: %w", err)
	}
	s.headMu.Lock()
	s.head = head
	s.headMu.Unlock()
	return nil
}

// Record implements audit.Recorder. It never blocks for longer than
// Options.FullWait; when the buffer stays full the event is dropped, counted
// and ErrQueueFull returned.
func (s *Store) Record(ctx context.Context, e audit.Event) error {
	if e.Action == "" {
		return errors.New("audit: event action is required")
	}
	if e.Outcome == "" {
		e.Outcome = audit.OutcomeSuccess
	}
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	if e.ID == "" {
		e.ID = newID(e.Time)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.dropped.Add(1)
		return ErrClosed
	}
	select {
	case s.q <- item{ev: e}:
		s.enqueued.Add(1)
		return nil
	default:
	}
	t := time.NewTimer(s.opts.FullWait)
	defer t.Stop()
	select {
	case s.q <- item{ev: e}:
		s.enqueued.Add(1)
		return nil
	case <-t.C:
	case <-ctx.Done():
	}
	s.dropped.Add(1)
	s.setErr(ErrQueueFull)
	s.log.Error("audit queue full; event dropped", "action", e.Action, "queue_cap", cap(s.q))
	return ErrQueueFull
}

// Flush waits until every event enqueued before the call has been written.
func (s *Store) Flush(ctx context.Context) error {
	done := make(chan struct{})
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrClosed
	}
	select {
	case s.q <- item{done: done}:
	case <-ctx.Done():
		s.mu.RUnlock()
		return ctx.Err()
	}
	s.mu.RUnlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops accepting events and waits (bounded by ctx) for the writer to
// drain the queue.
func (s *Store) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.q)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit: drain queue: %w", ctx.Err())
	}
}

// Subscribe registers fn to receive persisted entries after each committed
// batch. fn runs on the writer goroutine and MUST NOT block. The returned
// function unsubscribes.
func (s *Store) Subscribe(fn func([]Entry)) (cancel func()) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	id := s.nextID
	s.nextID++
	s.subs[id] = fn
	return func() {
		s.subMu.Lock()
		defer s.subMu.Unlock()
		delete(s.subs, id)
	}
}

// Metrics returns a snapshot of the recorder counters.
func (s *Store) Metrics() Metrics {
	s.statMu.Lock()
	defer s.statMu.Unlock()
	return Metrics{
		Enqueued: s.enqueued.Load(), Recorded: s.recorded.Load(), Dropped: s.dropped.Load(),
		WriteErrors: s.writeErrs.Load(), Pruned: s.pruned.Load(),
		QueueLen: len(s.q), QueueCap: cap(s.q),
		LastError: s.lastErr, LastErrorAt: s.lastErrAt, LastWriteAt: s.lastWriteAt,
	}
}

func (s *Store) setErr(err error) {
	s.statMu.Lock()
	s.lastErr, s.lastErrAt = err.Error(), s.now()
	s.statMu.Unlock()
}

func (s *Store) writer() {
	defer close(s.done)
	batch := make([]audit.Event, 0, s.opts.BatchSize)
	var markers []chan struct{}
	for it := range s.q {
		batch, markers = batch[:0], markers[:0]
		add := func(it item) {
			if it.done != nil {
				markers = append(markers, it.done)
			} else {
				batch = append(batch, it.ev)
			}
		}
		add(it)
	fill:
		for len(batch) < s.opts.BatchSize {
			select {
			case more, ok := <-s.q:
				if !ok {
					break fill
				}
				add(more)
			default:
				break fill
			}
		}
		if len(batch) > 0 {
			s.writeBatch(batch)
		}
		for _, m := range markers {
			close(m)
		}
	}
}

// writeBatch persists events with retries. The writer is the only goroutine
// extending the chain, so head is consistent.
func (s *Store) writeBatch(batch []audit.Event) {
	var entries []Entry
	var err error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		entries, err = s.insert(ctx, batch)
		cancel()
		if err == nil {
			break
		}
	}
	if err != nil {
		s.writeErrs.Add(uint64(len(batch)))
		s.setErr(err)
		s.log.Error("audit write failed; events lost", "count", len(batch), "err", err)
		return
	}
	s.recorded.Add(uint64(len(entries)))
	s.statMu.Lock()
	s.lastWriteAt = s.now()
	s.statMu.Unlock()
	s.subMu.RLock()
	subs := make([]func([]Entry), 0, len(s.subs))
	for _, fn := range s.subs {
		subs = append(subs, fn)
	}
	s.subMu.RUnlock()
	for _, fn := range subs {
		fn(entries)
	}
}

func (s *Store) insert(ctx context.Context, batch []audit.Event) ([]Entry, error) {
	s.headMu.Lock()
	defer s.headMu.Unlock()
	prev := s.head
	entries := make([]Entry, 0, len(batch))
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO audit_events
			(id, ts, actor_id, actor, action, target, outcome, reason, source_ip, user_agent, request_id, details, prev_hash, hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range batch {
			e.Time = e.Time.UTC().Truncate(time.Millisecond)
			raw, err := encodeDetails(e.Details)
			if err != nil {
				raw = `{"_error":"details not encodable"}`
			}
			c, err := canonicalJSON(e, raw)
			if err != nil {
				return err
			}
			h := ChainHash(prev, c)
			res, err := stmt.ExecContext(ctx, e.ID, e.Time.UnixMilli(), e.ActorID, e.Actor, e.Action, e.Target,
				string(e.Outcome), e.Reason, e.SourceIP, e.UserAgent, e.RequestID, raw, prev, h)
			if err != nil {
				return err
			}
			seq, _ := res.LastInsertId()
			e.Details = nil // hand subscribers the redacted, stored form
			if raw != "{}" {
				_ = json.Unmarshal([]byte(raw), &e.Details)
			}
			entries = append(entries, Entry{Event: e, Seq: seq, PrevHash: prev, Hash: h, rawDetails: raw})
			prev = h
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.head = prev
	return entries, nil
}

// Prune deletes events older than before (retention). It advances the chain
// anchor to the newest pruned event so verification still succeeds.
func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	var n int64
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var maxSeq sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(seq) FROM audit_events WHERE ts < ?`,
			before.UTC().UnixMilli()).Scan(&maxSeq); err != nil {
			return err
		}
		if !maxSeq.Valid {
			return nil
		}
		// Retention always removes a contiguous prefix of the chain (every
		// seq up to the newest expired event), keeping the rest verifiable.
		var hash string
		if err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_events WHERE seq = ?`, maxSeq.Int64).Scan(&hash); err != nil {
			return err
		}
		var cnt int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE seq <= ?`, maxSeq.Int64).Scan(&cnt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE audit_chain SET anchor_seq = ?, anchor_hash = ?,
			pruned_total = pruned_total + ?, updated_at = ? WHERE id = 1`,
			maxSeq.Int64, hash, cnt, s.now().UnixMilli()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE seq <= ?`, maxSeq.Int64); err != nil {
			return err
		}
		n = cnt
		return nil
	})
	if err == nil {
		s.pruned.Add(uint64(n))
	}
	return n, err
}

// newID returns a time-ordered random identifier (48-bit ms time + 80 random bits).
func newID(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:])
	return hex.EncodeToString(b[:])
}

const entryColumns = `seq, id, ts, actor_id, actor, action, target, outcome, reason, source_ip, user_agent, request_id, details, prev_hash, hash`

func prefixed(p string) string {
	cols := strings.Split(entryColumns, ", ")
	for i := range cols {
		cols[i] = p + cols[i]
	}
	return strings.Join(cols, ", ")
}

type scanner interface{ Scan(dest ...any) error }

func scanEntry(sc scanner) (Entry, error) {
	var en Entry
	var ts int64
	var outcome string
	if err := sc.Scan(&en.Seq, &en.ID, &ts, &en.ActorID, &en.Actor, &en.Action, &en.Target, &outcome,
		&en.Reason, &en.SourceIP, &en.UserAgent, &en.RequestID, &en.rawDetails, &en.PrevHash, &en.Hash); err != nil {
		return en, err
	}
	en.Time = time.UnixMilli(ts).UTC()
	en.Outcome = audit.Outcome(outcome)
	if en.rawDetails != "" && en.rawDetails != "{}" {
		_ = json.Unmarshal([]byte(en.rawDetails), &en.Details)
	}
	return en, nil
}

// scanEntryWithAnchor scans "anchor_seq, anchor_hash, <entry columns>" from a
// LEFT JOIN; null reports an empty audit_events table.
func scanEntryWithAnchor(sc scanner, aseq *int64, ahash *string) (Entry, bool, error) {
	var (
		seq, ts                                                 sql.NullInt64
		id, actorID, actor, action, target, outcome, reason     sql.NullString
		sourceIP, userAgent, requestID, details, prevHash, hash sql.NullString
	)
	if err := sc.Scan(aseq, ahash, &seq, &id, &ts, &actorID, &actor, &action, &target, &outcome, &reason,
		&sourceIP, &userAgent, &requestID, &details, &prevHash, &hash); err != nil {
		return Entry{}, false, err
	}
	if !seq.Valid {
		return Entry{}, true, nil
	}
	en := Entry{Seq: seq.Int64, PrevHash: prevHash.String, Hash: hash.String, rawDetails: details.String}
	en.ID, en.ActorID, en.Actor, en.Action, en.Target = id.String, actorID.String, actor.String, action.String, target.String
	en.Outcome, en.Reason, en.SourceIP = audit.Outcome(outcome.String), reason.String, sourceIP.String
	en.UserAgent, en.RequestID = userAgent.String, requestID.String
	en.Time = time.UnixMilli(ts.Int64).UTC()
	return en, false, nil
}
