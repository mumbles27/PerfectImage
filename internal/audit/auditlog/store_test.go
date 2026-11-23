package auditlog

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

func newStore(t *testing.T, db *store.DB, opts Options) *Store {
	t.Helper()
	s, err := New(context.Background(), db, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func record(t *testing.T, s *Store, evs ...audit.Event) {
	t.Helper()
	ctx := context.Background()
	for _, e := range evs {
		if err := s.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func seed(t *testing.T, s *Store, n int) {
	t.Helper()
	var evs []audit.Event
	for i := range n {
		evs = append(evs, audit.Event{
			Actor: fmt.Sprintf("user%d", i%3), Action: fmt.Sprintf("test.action%d", i%2),
			Target: fmt.Sprintf("item:%d", i), Outcome: audit.OutcomeSuccess,
			Details: map[string]any{"i": i, "password": "hunter2"},
		})
	}
	record(t, s, evs...)
}

func TestChainAndVerify(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	s := newStore(t, db, Options{})
	seed(t, s, 25)

	res, err := s.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Checked != 25 {
		t.Fatalf("verify = %+v", res)
	}
	// Each entry links to its predecessor.
	var prev = GenesisHash
	err = s.Each(ctx, Filter{}, func(e Entry) error {
		if e.PrevHash != prev {
			return fmt.Errorf("seq %d: prev %s want %s", e.Seq, e.PrevHash, prev)
		}
		if e.Details["password"] != audit.Redacted {
			return fmt.Errorf("seq %d: password not redacted: %v", e.Seq, e.Details)
		}
		prev = e.Hash
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.HeadHash != prev {
		t.Fatalf("head %s want %s", res.HeadHash, prev)
	}

	// The chain head survives a restart (new Store on the same DB).
	_ = s.Close(ctx)
	s2 := newStore(t, db, Options{})
	record(t, s2, audit.Event{Action: "after.restart"})
	if res, _ := s2.Verify(ctx); !res.OK || res.Checked != 26 {
		t.Fatalf("verify after restart = %+v", res)
	}
}

func TestVerifyEmpty(t *testing.T) {
	s := newStore(t, openDB(t), Options{})
	res, err := s.Verify(context.Background())
	if err != nil || !res.OK || res.Checked != 0 || res.HeadHash != GenesisHash {
		t.Fatalf("verify empty = %+v, %v", res, err)
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	s := newStore(t, db, Options{})
	seed(t, s, 3)
	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET actor = 'mallory' WHERE seq = 2`); err == nil ||
		!strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update allowed: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_events WHERE seq = 2`); err == nil {
		t.Fatal("delete allowed")
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_chain SET anchor_seq = -1`); err == nil {
		t.Fatal("anchor moved backwards")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		broken  int64
		problem string
	}{
		{"modified field", `UPDATE audit_events SET actor = 'mallory' WHERE seq = 5`, 5, "hash mismatch"},
		{"modified details", `UPDATE audit_events SET details = '{"i":99}' WHERE seq = 7`, 7, "hash mismatch"},
		{"deleted event", `DELETE FROM audit_events WHERE seq = 4`, 5, "prev_hash"},
		{"rehashed event", `UPDATE audit_events SET hash = 'ff' WHERE seq = 3`, 3, "hash mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			db := openDB(t)
			s := newStore(t, db, Options{})
			seed(t, s, 10)
			// Simulate an attacker with raw DB access: drop the guards first.
			for _, trg := range []string{"audit_events_no_update", "audit_events_no_delete"} {
				if _, err := db.ExecContext(ctx, `DROP TRIGGER `+trg); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.ExecContext(ctx, tt.sql); err != nil {
				t.Fatal(err)
			}
			res, err := s.Verify(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK || res.BrokenSeq != tt.broken || !strings.Contains(res.Problem, tt.problem) {
				t.Fatalf("verify = %+v", res)
			}
		})
	}
}

func TestPruneKeepsChainVerifiable(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	db := openDB(t)
	s := newStore(t, db, Options{Now: func() time.Time { return now }})
	for day := range 5 {
		record(t, s, audit.Event{Action: "old", Time: now.AddDate(0, 0, day-9)}, audit.Event{Action: "old2", Time: now.AddDate(0, 0, day-9)})
	}
	record(t, s, audit.Event{Action: "new"})
	n, err := s.Prune(ctx, now.AddDate(0, 0, -6)) // removes days -9..-7 (6 events)
	if err != nil || n != 6 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	res, err := s.Verify(ctx)
	if err != nil || !res.OK || res.Checked != 5 || res.AnchorSeq != 6 {
		t.Fatalf("verify after prune = %+v, %v", res, err)
	}
	if n, _ := s.Prune(ctx, now.AddDate(0, 0, -6)); n != 0 {
		t.Fatalf("second prune removed %d", n)
	}
	record(t, s, audit.Event{Action: "after.prune"})
	if res, _ := s.Verify(ctx); !res.OK || res.Checked != 6 {
		t.Fatalf("verify = %+v", res)
	}
	if m := s.Metrics(); m.Pruned != 6 {
		t.Fatalf("metrics %+v", m)
	}
}

func TestQueryFilters(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s := newStore(t, openDB(t), Options{})
	record(t, s,
		audit.Event{Time: base, Actor: "alice", Action: "auth.login", Outcome: audit.OutcomeSuccess, Target: "user:alice"},
		audit.Event{Time: base.Add(time.Hour), Actor: "bob", Action: "auth.login", Outcome: audit.OutcomeFailure, Target: "user:bob"},
		audit.Event{Time: base.Add(2 * time.Hour), Actor: "alice", Action: "image.build.start", Outcome: audit.OutcomeSuccess, Target: "job:1"},
		audit.Event{Time: base.Add(3 * time.Hour), Actor: "carol", Action: "authz.deny", Outcome: audit.OutcomeDenied, Target: "GET /x_y%"},
	)
	tests := []struct {
		name string
		f    Filter
		want []string // actions, newest first
	}{
		{"all", Filter{}, []string{"authz.deny", "image.build.start", "auth.login", "auth.login"}},
		{"actor", Filter{Actor: "ALI"}, []string{"image.build.start", "auth.login"}},
		{"action prefix", Filter{Action: "auth."}, []string{"auth.login", "auth.login"}},
		{"outcome", Filter{Outcome: "denied"}, []string{"authz.deny"}},
		{"target", Filter{Target: "user:"}, []string{"auth.login", "auth.login"}},
		{"like escaped", Filter{Target: "x_y%"}, []string{"authz.deny"}},
		{"like literal underscore", Filter{Target: "x_z"}, nil},
		{"time range", Filter{From: base.Add(time.Hour), To: base.Add(3 * time.Hour)}, []string{"image.build.start", "auth.login"}},
		{"page", Filter{Limit: 2, Offset: 2}, []string{"auth.login", "auth.login"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, total, err := s.Query(ctx, tt.f)
			if err != nil {
				t.Fatal(err)
			}
			var actions []string
			for _, e := range got {
				actions = append(actions, e.Action)
			}
			if fmt.Sprint(actions) != fmt.Sprint(tt.want) {
				t.Fatalf("got %v want %v", actions, tt.want)
			}
			if tt.f.Limit == 0 && total != len(tt.want) {
				t.Fatalf("total %d want %d", total, len(tt.want))
			}
		})
	}
}

func TestQueueFullDrops(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	s := newStore(t, db, Options{QueueSize: 2, FullWait: time.Millisecond})
	// Block the writer: subscribers run on the writer goroutine.
	release := make(chan struct{})
	var once sync.Once
	s.Subscribe(func([]Entry) { once.Do(func() { <-release }) })
	_ = s.Record(ctx, audit.Event{Action: "a"})
	time.Sleep(50 * time.Millisecond) // writer picks up "a" and blocks in the subscriber
	var dropped int
	for range 10 {
		if err := s.Record(ctx, audit.Event{Action: "b"}); err == ErrQueueFull {
			dropped++
		}
	}
	close(release)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	m := s.Metrics()
	if dropped == 0 || m.Dropped != uint64(dropped) || m.Recorded+m.Dropped != 11 || m.LastError == "" {
		t.Fatalf("dropped=%d metrics=%+v", dropped, m)
	}
	if res, _ := s.Verify(ctx); !res.OK {
		t.Fatalf("verify %+v", res)
	}
}

func TestRecordAfterCloseAndValidation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, openDB(t), Options{})
	if err := s.Record(ctx, audit.Event{}); err == nil {
		t.Fatal("event without action accepted")
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, audit.Event{Action: "x"}); err != ErrClosed {
		t.Fatalf("record after close: %v", err)
	}
}

func TestSubscribeReceivesPersistedEntries(t *testing.T) {
	s := newStore(t, openDB(t), Options{})
	var mu sync.Mutex
	var got []Entry
	cancel := s.Subscribe(func(es []Entry) {
		mu.Lock()
		got = append(got, es...)
		mu.Unlock()
	})
	record(t, s, audit.Event{Action: "x", Details: map[string]any{"token": "t"}})
	cancel()
	record(t, s, audit.Event{Action: "y"})
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Hash == "" || got[0].Seq == 0 || got[0].Details["token"] != audit.Redacted {
		t.Fatalf("got %+v", got)
	}
}
