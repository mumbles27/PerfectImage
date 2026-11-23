package jobs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/store"
)

func newTestManager(t *testing.T, workers int) *Manager {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "jobs.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return New(db, Options{Workers: workers, PollInterval: 20 * time.Millisecond})
}

func start(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
}

func waitStatus(t *testing.T, m *Manager, id string, want Status) *Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := m.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status == want {
			return j
		}
		if j.Status.Terminal() {
			t.Fatalf("job %s reached %s (err %q), want %s", id, j.Status, j.Error, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", want)
	return nil
}

func TestJobOutcomes(t *testing.T) {
	type payload struct{ N int }
	tests := []struct {
		name       string
		handler    HandlerFunc
		wantStatus Status
		wantErr    string
		wantResult string
		wantLogs   []string
	}{
		{
			name: "success with result and logs",
			handler: func(ctx context.Context, j *Job, log *LogWriter) (any, error) {
				var p payload
				if err := j.DecodePayload(&p); err != nil {
					return nil, err
				}
				log.Printf("step %d", p.N)
				fmt.Fprint(log, "partial ")
				fmt.Fprint(log, "line\nlast-no-newline")
				return map[string]int{"n": p.N * 2}, nil
			},
			wantStatus: StatusSucceeded,
			wantResult: `{"n":14}`,
			wantLogs:   []string{"step 7", "partial line", "last-no-newline"},
		},
		{
			name: "error",
			handler: func(ctx context.Context, j *Job, log *LogWriter) (any, error) {
				return nil, errors.New("boom")
			},
			wantStatus: StatusFailed,
			wantErr:    "boom",
		},
		{
			name: "panic",
			handler: func(ctx context.Context, j *Job, log *LogWriter) (any, error) {
				panic("kaboom")
			},
			wantStatus: StatusFailed,
			wantErr:    "panic: kaboom",
			wantLogs:   []string{"internal error: handler panicked (see service log)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager(t, 2)
			if err := m.Register("test", tt.handler); err != nil {
				t.Fatal(err)
			}
			start(t, m)
			id, err := m.Enqueue(context.Background(), "test", payload{N: 7}, "alice")
			if err != nil {
				t.Fatal(err)
			}
			j := waitStatus(t, m, id, tt.wantStatus)
			if !strings.Contains(j.Error, tt.wantErr) {
				t.Errorf("Error = %q, want %q", j.Error, tt.wantErr)
			}
			if string(j.Result) != tt.wantResult {
				t.Errorf("Result = %s, want %s", j.Result, tt.wantResult)
			}
			if j.CreatedBy != "alice" || j.StartedAt == nil || j.FinishedAt == nil {
				t.Errorf("job metadata = %+v", j)
			}
			logs, err := m.Logs(context.Background(), id, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, l := range logs {
				got = append(got, l.Line)
			}
			if strings.Join(got, "|") != strings.Join(tt.wantLogs, "|") {
				t.Errorf("logs = %q, want %q", got, tt.wantLogs)
			}
		})
	}
}

func TestRegisterAndEnqueueErrors(t *testing.T) {
	m := newTestManager(t, 1)
	h := HandlerFunc(func(context.Context, *Job, *LogWriter) (any, error) { return nil, nil })
	if err := m.Register("a", h); err != nil {
		t.Fatal(err)
	}
	if err := m.Register("a", h); err == nil {
		t.Error("duplicate register accepted")
	}
	if _, err := m.Enqueue(context.Background(), "nope", nil, ""); !errors.Is(err, ErrUnknownType) {
		t.Errorf("Enqueue unknown = %v", err)
	}
	start(t, m)
	if err := m.Register("b", h); !errors.Is(err, ErrStarted) {
		t.Errorf("Register after start = %v", err)
	}
	if _, err := m.Get(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing = %v", err)
	}
	if err := m.Cancel(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Cancel missing = %v", err)
	}
}

func TestCancelRunningAndQueued(t *testing.T) {
	m := newTestManager(t, 1)
	started := make(chan string, 4)
	if err := m.Register("block", HandlerFunc(func(ctx context.Context, j *Job, log *LogWriter) (any, error) {
		started <- j.ID
		<-ctx.Done()
		log.Printf("cleanup after cancel")
		return nil, ctx.Err()
	})); err != nil {
		t.Fatal(err)
	}
	start(t, m)
	ctx := context.Background()
	first, _ := m.Enqueue(ctx, "block", nil, "")
	second, _ := m.Enqueue(ctx, "block", nil, "")
	if got := <-started; got != first {
		t.Fatalf("started %s, want %s", got, first)
	}
	// Single worker: second is still queued.
	if err := m.Cancel(ctx, second); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, m, second, StatusCanceled)

	events, unsub := m.Subscribe(first)
	defer unsub()
	if err := m.Cancel(ctx, first); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, m, first, StatusCanceled)
	if err := m.Cancel(ctx, first); !errors.Is(err, ErrNotCancelable) {
		t.Errorf("cancel finished job = %v", err)
	}
	var sawLog, sawStatus bool
	timeout := time.After(2 * time.Second)
	for !(sawLog && sawStatus) {
		select {
		case e := <-events:
			if e.Kind == EventLog && e.Line.Line == "cleanup after cancel" {
				sawLog = true
			}
			if e.Kind == EventStatus && e.Status == StatusCanceled {
				sawStatus = true
			}
		case <-timeout:
			t.Fatalf("missing events: log=%v status=%v", sawLog, sawStatus)
		}
	}
	counts, err := m.Counts(ctx)
	if err != nil || counts[StatusCanceled] != 2 {
		t.Errorf("Counts = %v, %v", counts, err)
	}
}

func TestShutdownAndRecovery(t *testing.T) {
	m := newTestManager(t, 1)
	running := make(chan struct{})
	if err := m.Register("block", HandlerFunc(func(ctx context.Context, j *Job, log *LogWriter) (any, error) {
		close(running)
		<-ctx.Done()
		return nil, ctx.Err()
	})); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	id, _ := m.Enqueue(context.Background(), "block", nil, "")
	<-running
	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := m.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	j, _ := m.Get(context.Background(), id)
	if j.Status != StatusFailed || !strings.Contains(j.Error, "shutdown") {
		t.Fatalf("after shutdown job = %s %q", j.Status, j.Error)
	}

	// Simulate a crash leaving a job "running", then restart.
	if _, err := m.db.Exec(`UPDATE jobs SET status='running', error=NULL WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	m2 := New(m.db, Options{Workers: 1})
	start(t, m2)
	j, _ = m2.Get(context.Background(), id)
	if j.Status != StatusFailed || !strings.Contains(j.Error, "restarted") {
		t.Fatalf("after restart job = %s %q", j.Status, j.Error)
	}
}

func TestListFilters(t *testing.T) {
	m := newTestManager(t, 1)
	h := HandlerFunc(func(context.Context, *Job, *LogWriter) (any, error) { return nil, nil })
	_ = m.Register("a", h)
	_ = m.Register("b", h)
	ctx := context.Background()
	for _, typ := range []string{"a", "a", "b"} {
		if _, err := m.Enqueue(ctx, typ, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		opts ListOptions
		want int
	}{
		{ListOptions{}, 3},
		{ListOptions{Type: "a"}, 2},
		{ListOptions{Status: StatusQueued, Type: "b"}, 1},
		{ListOptions{Status: StatusRunning}, 0},
		{ListOptions{Limit: 1}, 1},
		{ListOptions{Offset: 2}, 1},
	}
	for _, tt := range tests {
		got, err := m.List(ctx, tt.opts)
		if err != nil || len(got) != tt.want {
			t.Errorf("List(%+v) = %d, %v; want %d", tt.opts, len(got), err, tt.want)
		}
	}
}

func TestLogWriterLongLinesAndConcurrency(t *testing.T) {
	m := newTestManager(t, 1)
	ctx := context.Background()
	_ = m.Register("x", HandlerFunc(func(context.Context, *Job, *LogWriter) (any, error) { return nil, nil }))
	id, _ := m.Enqueue(ctx, "x", nil, "")
	w := newLogWriter(m, id)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for k := 0; k < 10; k++ {
				fmt.Fprintf(w, "g%d-%d\n", i, k)
			}
		}(i)
	}
	wg.Wait()
	_, _ = w.Write([]byte(strings.Repeat("y", MaxLineBytes+10)))
	w.Flush()
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}
	logs, _ := m.Logs(ctx, id, 0, 0)
	if len(logs) != 42 {
		t.Fatalf("got %d lines, want 42", len(logs))
	}
	if len(logs[40].Line) != MaxLineBytes || len(logs[41].Line) != 10 {
		t.Errorf("long line split = %d, %d", len(logs[40].Line), len(logs[41].Line))
	}
	after, _ := m.Logs(ctx, id, logs[39].ID, 0)
	if len(after) != 2 {
		t.Errorf("Logs afterID = %d lines", len(after))
	}
}

func TestHubUnsubscribe(t *testing.T) {
	h := NewHub()
	ch, unsub := h.Subscribe("j")
	all, unsubAll := h.Subscribe("")
	h.Publish(Event{Kind: EventStatus, JobID: "j", Status: StatusRunning})
	if e := <-ch; e.Status != StatusRunning {
		t.Fatal("subscriber missed event")
	}
	if e := <-all; e.JobID != "j" {
		t.Fatal("wildcard subscriber missed event")
	}
	unsub()
	unsub() // idempotent
	unsubAll()
	h.Publish(Event{JobID: "j"}) // must not panic on closed channels
	if _, ok := <-ch; ok {
		t.Fatal("channel not closed")
	}
}
