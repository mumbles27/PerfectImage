// Package jobs is a persistent, SQLite-backed background job queue.
//
// Domain packages register a Handler per job type before the manager starts:
//
//	mgr.Register("packer.build", jobs.HandlerFunc(func(ctx context.Context, j *jobs.Job, log *jobs.LogWriter) (any, error) {
//		var p BuildPayload
//		if err := j.DecodePayload(&p); err != nil { return nil, err }
//		log.Printf("building %s", p.Template)
//		return BuildResult{TemplateID: 9000}, nil
//	}))
//
// and enqueue with mgr.Enqueue(ctx, "packer.build", payload, principal.Username).
//
// Handlers must honour ctx cancellation (user cancel or service shutdown) and
// must never write secrets to the LogWriter: job logs are visible in the UI.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Status is a job lifecycle state.
type Status string

// Job statuses. Transitions: queued -> running -> succeeded|failed|canceled,
// and queued -> canceled.
const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCanceled  Status = "canceled"
)

// Terminal reports whether s is a final state.
func (s Status) Terminal() bool {
	return s == StatusSucceeded || s == StatusFailed || s == StatusCanceled
}

// Errors.
var (
	ErrNotFound      = errors.New("jobs: job not found")
	ErrUnknownType   = errors.New("jobs: unknown job type")
	ErrNotCancelable = errors.New("jobs: job is already finished")
	ErrStarted       = errors.New("jobs: manager already started")
)

// Job is a persisted unit of background work.
type Job struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Status     Status          `json:"status"`
	Payload    json.RawMessage `json:"payload"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

// DecodePayload unmarshals the job payload into v.
func (j *Job) DecodePayload(v any) error { return json.Unmarshal(j.Payload, v) }

// Duration returns the run time so far (or total, when finished).
func (j *Job) Duration() time.Duration {
	if j.StartedAt == nil {
		return 0
	}
	end := time.Now()
	if j.FinishedAt != nil {
		end = *j.FinishedAt
	}
	return end.Sub(*j.StartedAt).Round(time.Second)
}

// Handler executes jobs of one type. The returned result (may be nil) is
// stored as JSON on success.
type Handler interface {
	Run(ctx context.Context, job *Job, log *LogWriter) (result any, err error)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, job *Job, log *LogWriter) (any, error)

// Run implements Handler.
func (f HandlerFunc) Run(ctx context.Context, job *Job, log *LogWriter) (any, error) {
	return f(ctx, job, log)
}

// LogLine is a stored job log line.
type LogLine struct {
	ID    int64     `json:"id"`
	JobID string    `json:"job_id"`
	Time  time.Time `json:"time"`
	Line  string    `json:"line"`
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	// Prefix with a millisecond timestamp so IDs sort roughly by creation.
	ts := uint64(time.Now().UnixMilli())
	var t [6]byte
	for i := 5; i >= 0; i-- {
		t[i] = byte(ts)
		ts >>= 8
	}
	return hex.EncodeToString(t[:]) + hex.EncodeToString(b[:])
}

func ms(t time.Time) int64 { return t.UTC().UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }
