package siem

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/config"
)

// countingWebhook returns a server that fails while down is true and counts
// delivered events.
func countingWebhook(t *testing.T, down *atomic.Bool, status int) (string, *atomic.Int64) {
	t.Helper()
	var delivered atomic.Int64
	srv, _ := captureServer(t, func(w http.ResponseWriter, _ *http.Request, body []byte) {
		if down.Load() {
			w.WriteHeader(status)
			return
		}
		var p struct {
			Events []Record `json:"events"`
		}
		_ = json.Unmarshal(body, &p)
		delivered.Add(int64(len(p.Events)))
	})
	return srv.URL, &delivered
}

func entries(n int) []auditlog.Entry {
	out := make([]auditlog.Entry, n)
	for i := range out {
		out[i] = testEntry()
		out[i].ID = ""
	}
	return out
}

func TestRetryWithSpill(t *testing.T) {
	shortBackoff(t)
	var down atomic.Bool
	down.Store(true)
	url, delivered := countingWebhook(t, &down, http.StatusServiceUnavailable)
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeWebhook, URL: url, BatchSize: 5}, staticCreds{})

	m.PublishAudit(entries(12))
	waitFor(t, "records spilled", func() bool {
		st := m.Statuses()[0]
		return st.Failed > 0 && st.Spilled == 12 && st.SpilledBytes > 0
	})
	if st := m.Statuses()[0]; st.Healthy() || !strings.Contains(st.LastError, "503") {
		t.Fatalf("status while down %+v", st)
	}
	down.Store(false)
	waitFor(t, "backlog delivered", func() bool { return delivered.Load() == 12 })
	waitFor(t, "spill drained", func() bool {
		st := m.Statuses()[0]
		return st.Spilled == 0 && st.Sent == 12 && st.Healthy()
	})
	if st := m.Statuses()[0]; st.Dropped != 0 {
		t.Fatalf("dropped %+v", st)
	}
}

func TestSpillSurvivesRestart(t *testing.T) {
	shortBackoff(t)
	var down atomic.Bool
	down.Store(true)
	url, delivered := countingWebhook(t, &down, http.StatusBadGateway)
	cfg, _ := outputCfg(t, config.SIEMOutput{Type: config.SIEMTypeWebhook, URL: url})

	m1, err := NewManager(cfg, staticCreds{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	m1.PublishAudit(entries(4))
	waitFor(t, "first failure", func() bool { return m1.Statuses()[0].Failed > 0 })
	m1.PublishAudit(entries(3)) // queued behind the backlog
	if err := m1.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if delivered.Load() != 0 {
		t.Fatal("delivered while down")
	}

	down.Store(false)
	m2, err := NewManager(cfg, staticCreds{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close(context.Background())
	if st := m2.Statuses()[0]; st.Spilled != 7 {
		t.Fatalf("spill after restart %+v", st)
	}
	waitFor(t, "spill delivered after restart", func() bool { return delivered.Load() == 7 })
}

func TestSpillCapDrops(t *testing.T) {
	shortBackoff(t)
	var down atomic.Bool
	down.Store(true)
	url, _ := countingWebhook(t, &down, http.StatusServiceUnavailable)
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeWebhook, URL: url, SpillMaxMB: 1, BatchSize: 50}, staticCreds{})
	// ~1 KiB per record: 3000 records exceed the 1 MiB cap.
	big := entries(1)[0]
	big.Details = map[string]any{"blob": strings.Repeat("x", 1000)}
	for range 60 {
		batch := make([]auditlog.Entry, 50)
		for i := range batch {
			batch[i] = big
		}
		m.PublishAudit(batch)
		time.Sleep(2 * time.Millisecond)
	}
	waitFor(t, "drops", func() bool {
		st := m.Statuses()[0]
		return st.Dropped > 0 && st.SpilledBytes > 0 && st.SpilledBytes <= 1<<20
	})
}

func TestPermanentErrorDrops(t *testing.T) {
	shortBackoff(t)
	var down atomic.Bool
	down.Store(true)
	url, _ := countingWebhook(t, &down, http.StatusBadRequest)
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeWebhook, URL: url}, staticCreds{})
	m.PublishAudit(entries(3))
	waitFor(t, "permanent drop", func() bool {
		st := m.Statuses()[0]
		return st.Dropped == 3 && st.Failed == 1 && st.Spilled == 0
	})
}

func TestMemoryBacklogWithoutSpill(t *testing.T) {
	shortBackoff(t)
	var down atomic.Bool
	down.Store(true)
	url, delivered := countingWebhook(t, &down, http.StatusServiceUnavailable)
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeWebhook, URL: url, SpillMaxMB: -1, QueueSize: 10, BatchSize: 4}, staticCreds{})
	m.PublishAudit(entries(8))
	waitFor(t, "failure", func() bool { return m.Statuses()[0].Failed > 1 })
	down.Store(false)
	waitFor(t, "memory backlog delivered", func() bool { return delivered.Load() == 8 })
}

func TestQueueFullDropsWithoutBlocking(t *testing.T) {
	var down atomic.Bool
	url, _ := countingWebhook(t, &down, 0)
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeWebhook, URL: url, QueueSize: 1, FlushInterval: time.Hour, BatchSize: 1000}, staticCreds{})
	// Fill the queue faster than the worker can batch it; must never block.
	done := make(chan struct{})
	go func() {
		for range 1000 {
			m.PublishAudit(entries(1))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PublishAudit blocked")
	}
	if m.Statuses()[0].Dropped == 0 {
		t.Fatal("expected drops with a 1-slot queue")
	}
}

func TestLogSinkLevelsAndLoopGuard(t *testing.T) {
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeFile, Path: t.TempDir() + "/x.jsonl",
		Streams: []string{"logs"}, MinLevel: "warn"}, nil)
	s := logSink{m: m}
	if s.Enabled(slog.LevelInfo) || !s.Enabled(slog.LevelWarn) {
		t.Fatal("sink level filter")
	}
	ctx := context.Background()
	r := slog.NewRecord(time.Now(), slog.LevelError, "boom", 0)
	_ = s.Emit(ctx, r)
	own := slog.NewRecord(time.Now(), slog.LevelError, "siem delivery failed", 0)
	own.AddAttrs(slog.String("component", "siem"))
	_ = s.Emit(ctx, own)
	m.PublishAudit(entries(1)) // audit stream not selected
	waitFor(t, "one log delivered", func() bool { return m.Statuses()[0].Sent == 1 })
	time.Sleep(50 * time.Millisecond)
	if st := m.Statuses()[0]; st.Sent != 1 {
		t.Fatalf("status %+v", st)
	}
}

func TestDisabledOutput(t *testing.T) {
	m := newTestManager(t, config.SIEMOutput{Type: config.SIEMTypeFile, Path: t.TempDir() + "/x", Disabled: true}, nil)
	st := m.Statuses()
	if len(st) != 1 || st[0].Enabled {
		t.Fatalf("status %+v", st)
	}
	if err := m.Test(context.Background(), "test", "x"); err != ErrUnknownOutput {
		t.Fatalf("test on disabled: %v", err)
	}
}
