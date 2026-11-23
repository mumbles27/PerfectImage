// Package audit defines the audit event model and the Recorder interface.
//
// The foundation only provides the types, a no-op recorder and a swappable
// recorder. Persistence, querying and the Audit UI are owned by the ops agent,
// which installs a real Recorder via Swappable.Set during plugin init.
package audit

import (
	"context"
	"sync/atomic"
	"time"
)

// Outcome is the result of an audited action.
type Outcome string

// Outcomes.
const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Event is a single security-relevant action. Never put secret values
// (passwords, tokens, keys) in any field, including Details.
type Event struct {
	ID        string         `json:"id,omitempty"` // assigned by the recorder if empty
	Time      time.Time      `json:"time"`         // set by the recorder if zero
	ActorID   string         `json:"actor_id,omitempty"`
	Actor     string         `json:"actor,omitempty"`  // username or "system"
	Action    string         `json:"action"`           // dotted verb, e.g. "image.build.start"
	Target    string         `json:"target,omitempty"` // e.g. "job:01H..." or "user:alice"
	Outcome   Outcome        `json:"outcome"`
	Reason    string         `json:"reason,omitempty"`
	SourceIP  string         `json:"source_ip,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// Recorder persists or forwards audit events. Implementations must be safe
// for concurrent use.
type Recorder interface {
	Record(ctx context.Context, e Event) error
}

// NopRecorder discards events.
type NopRecorder struct{}

// Record implements Recorder.
func (NopRecorder) Record(context.Context, Event) error { return nil }

// RecorderFunc adapts a function to Recorder.
type RecorderFunc func(ctx context.Context, e Event) error

// Record implements Recorder.
func (f RecorderFunc) Record(ctx context.Context, e Event) error { return f(ctx, e) }

// Swappable is a Recorder whose implementation can be replaced at runtime.
// The app hands one Swappable to every component; the ops agent calls Set.
type Swappable struct {
	v atomic.Value // holds recorderBox
}

type recorderBox struct{ r Recorder }

// NewSwappable returns a Swappable initialised to NopRecorder.
func NewSwappable() *Swappable {
	s := &Swappable{}
	s.Set(nil)
	return s
}

// Set installs r (nil means NopRecorder).
func (s *Swappable) Set(r Recorder) {
	if r == nil {
		r = NopRecorder{}
	}
	s.v.Store(recorderBox{r})
}

// Record implements Recorder.
func (s *Swappable) Record(ctx context.Context, e Event) error {
	b, _ := s.v.Load().(recorderBox)
	if b.r == nil {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	return b.r.Record(ctx, e)
}
