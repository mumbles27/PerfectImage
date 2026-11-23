// Package logging configures log/slog JSON output to stdout and a rotating
// file, and fans records out to pluggable Sinks (e.g. SIEM forwarders owned
// by internal/siem).
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Sink receives every log record at or above its own level after the main
// handlers. Implementations MUST NOT block (buffer and drop or forward
// asynchronously) and MUST NOT log through the same logger (to avoid loops).
// Attributes added with Logger.With are included in the record; attributes
// inside groups are flattened with dotted keys ("group.key").
type Sink interface {
	Name() string
	Enabled(level slog.Level) bool
	Emit(ctx context.Context, r slog.Record) error
	Close() error
}

// Options configures Setup.
type Options struct {
	Level      string // debug, info, warn, error
	Stdout     io.Writer
	File       string // rotating log file path; empty disables file output
	MaxSizeMB  int
	MaxBackups int
}

// Logging owns the root logger, its outputs and registered sinks.
type Logging struct {
	Logger *slog.Logger
	level  *slog.LevelVar
	file   *RotatingFile

	mu    sync.RWMutex
	sinks []Sink
}

// ParseLevel converts a config level string to slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("logging: unknown level %q", s)
}

// Setup builds the root logger.
func Setup(opts Options) (*Logging, error) {
	lvl, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	l := &Logging{level: new(slog.LevelVar)}
	l.level.Set(lvl)

	var writers []io.Writer
	if opts.Stdout != nil {
		writers = append(writers, opts.Stdout)
	}
	if opts.File != "" {
		f, err := NewRotatingFile(opts.File, int64(opts.MaxSizeMB)*1024*1024, opts.MaxBackups)
		if err != nil {
			return nil, err
		}
		l.file = f
		writers = append(writers, f)
	}
	var out io.Writer = io.Discard
	switch len(writers) {
	case 1:
		out = writers[0]
	case 0:
	default:
		out = io.MultiWriter(writers...)
	}
	base := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: l.level})
	l.Logger = slog.New(&fanout{base: base, l: l})
	return l, nil
}

// SetLevel changes the minimum level at runtime.
func (l *Logging) SetLevel(lvl slog.Level) { l.level.Set(lvl) }

// AddSink registers a sink. Safe for concurrent use.
func (l *Logging) AddSink(s Sink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sinks = append(l.sinks, s)
}

func (l *Logging) snapshot() []Sink {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sinks
}

// Close closes sinks and the log file.
func (l *Logging) Close() error {
	l.mu.Lock()
	sinks := l.sinks
	l.sinks = nil
	l.mu.Unlock()
	var firstErr error
	for _, s := range sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if l.file != nil {
		if err := l.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// fanout writes to the base JSON handler and forwards to sinks.
type fanout struct {
	base   slog.Handler
	l      *Logging
	attrs  []slog.Attr // already flattened with group prefix
	prefix string      // current group prefix, "a.b."
}

func (h *fanout) Enabled(ctx context.Context, lvl slog.Level) bool {
	if h.base.Enabled(ctx, lvl) {
		return true
	}
	for _, s := range h.l.snapshot() {
		if s.Enabled(lvl) {
			return true
		}
	}
	return false
}

func (h *fanout) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.base.Enabled(ctx, r.Level) {
		err = h.base.Handle(ctx, r)
	}
	sinks := h.l.snapshot()
	if len(sinks) == 0 {
		return err
	}
	flat := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	flat.AddAttrs(h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		flat.AddAttrs(flatten(h.prefix, a)...)
		return true
	})
	for _, s := range sinks {
		if s.Enabled(r.Level) {
			// Sink errors are intentionally dropped: logging them would loop.
			_ = s.Emit(ctx, flat.Clone())
		}
	}
	return err
}

func (h *fanout) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.base = h.base.WithAttrs(as)
	n.attrs = append([]slog.Attr(nil), h.attrs...)
	for _, a := range as {
		n.attrs = append(n.attrs, flatten(h.prefix, a)...)
	}
	return &n
}

func (h *fanout) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	n := *h
	n.base = h.base.WithGroup(name)
	n.prefix = h.prefix + name + "."
	return &n
}

func flatten(prefix string, a slog.Attr) []slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() != slog.KindGroup {
		if a.Key == "" {
			return nil
		}
		a.Key = prefix + a.Key
		return []slog.Attr{a}
	}
	p := prefix
	if a.Key != "" {
		p = prefix + a.Key + "."
	}
	var out []slog.Attr
	for _, g := range a.Value.Group() {
		out = append(out, flatten(p, g)...)
	}
	return out
}

// Discard returns a logger that drops everything (for tests).
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// StdoutIfEnabled returns os.Stdout or nil.
func StdoutIfEnabled(enabled bool) io.Writer {
	if enabled {
		return os.Stdout
	}
	return nil
}
