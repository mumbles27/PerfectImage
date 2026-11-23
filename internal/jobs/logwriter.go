package jobs

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxLineBytes caps a single stored log line.
const MaxLineBytes = 8 << 10

// LogWriter is an io.Writer that splits output into lines, stores each line in
// job_logs and publishes it to the hub. It is safe for concurrent use, so it
// can be used as both Stdout and Stderr of an exec.Cmd.
type LogWriter struct {
	m     *Manager
	jobID string

	mu  sync.Mutex
	buf bytes.Buffer
	err error
}

func newLogWriter(m *Manager, jobID string) *LogWriter {
	return &LogWriter{m: m, jobID: jobID}
}

// Write implements io.Writer.
func (w *LogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			if w.buf.Len() > MaxLineBytes {
				w.emit(w.buf.Next(MaxLineBytes))
				continue
			}
			break
		}
		w.emit(w.buf.Next(i + 1))
	}
	return len(p), nil
}

// Printf writes a formatted line.
func (w *LogWriter) Printf(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	_, _ = w.Write([]byte(s))
}

// Flush stores any buffered partial line.
func (w *LogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		w.emit(w.buf.Next(w.buf.Len()))
	}
}

// Err returns the first storage error encountered, if any.
func (w *LogWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *LogWriter) emit(b []byte) {
	line := strings.TrimRight(string(b), "\r\n")
	if len(line) > MaxLineBytes {
		line = line[:MaxLineBytes]
	}
	line = strings.ToValidUTF8(line, string(utf8.RuneError))
	// Use a background context so log lines written while a job is being
	// canceled are still persisted.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := w.m.AppendLog(ctx, w.jobID, line); err != nil && w.err == nil {
		w.err = err
	}
}
