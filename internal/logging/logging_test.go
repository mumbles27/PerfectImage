package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type memSink struct {
	mu   sync.Mutex
	min  slog.Level
	recs []map[string]any
}

func (m *memSink) Name() string              { return "mem" }
func (m *memSink) Enabled(l slog.Level) bool { return l >= m.min }
func (m *memSink) Close() error              { return nil }
func (m *memSink) Emit(_ context.Context, r slog.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := map[string]any{"msg": r.Message, "level": r.Level.String()}
	r.Attrs(func(a slog.Attr) bool { rec[a.Key] = a.Value.Any(); return true })
	m.recs = append(m.recs, rec)
	return nil
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in   string
		want slog.Level
		err  bool
	}{
		{"debug", slog.LevelDebug, false},
		{"INFO", slog.LevelInfo, false},
		{"", slog.LevelInfo, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"loud", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.in)
		if (err != nil) != tt.err || got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, %v", tt.in, got, err)
		}
	}
}

func TestSetupJSONAndSinks(t *testing.T) {
	var buf bytes.Buffer
	l, err := Setup(Options{Level: "info", Stdout: &buf})
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{min: slog.LevelDebug}
	l.AddSink(sink)

	log := l.Logger.With("component", "test").WithGroup("req").With("id", "r1")
	log.Info("hello", "path", "/x", slog.Group("user", "name", "bob"))
	log.Debug("hidden from base") // below base level, but sink wants debug

	var rec map[string]any
	line, _, _ := strings.Cut(buf.String(), "\n")
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("not JSON: %q", buf.String())
	}
	if rec["msg"] != "hello" || rec["component"] != "test" {
		t.Errorf("base record = %v", rec)
	}
	if strings.Contains(buf.String(), "hidden") {
		t.Error("debug record written to base handler")
	}

	if len(sink.recs) != 2 {
		t.Fatalf("sink got %d records", len(sink.recs))
	}
	got := sink.recs[0]
	for k, want := range map[string]any{"component": "test", "req.id": "r1", "req.path": "/x", "req.user.name": "bob"} {
		if got[k] != want {
			t.Errorf("sink[%s] = %v, want %v (all: %v)", k, got[k], want, got)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "app.log")
	r, err := NewRotatingFile(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 39) + "\n" // 40 bytes
	for i := 0; i < 10; i++ {
		if _, err := fmt.Fprint(r, line); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"app.log", "app.log.1", "app.log.2"} {
		fi, err := os.Stat(filepath.Join(dir, "logs", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Size() > 100 {
			t.Errorf("%s size %d > max", name, fi.Size())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "logs", "app.log.3")); !os.IsNotExist(err) {
		t.Error("kept more than maxBackups files")
	}
	if _, err := r.Write([]byte("x")); err == nil {
		t.Error("write after close succeeded")
	}
}
