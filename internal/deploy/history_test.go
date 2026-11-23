package deploy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/store"
)

// TestHistoryOrdering checks that a late Queued (the web handler records it
// after Enqueue, racing the worker) never moves a deployment backwards.
func TestHistoryOrdering(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "pi.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	h := NewHistoryStore(db)
	req := linuxRequest()

	tests := []struct {
		name  string
		calls func(id string) error
		want  string
	}{
		{"normal order", func(id string) error {
			return firstErr(h.Queued(ctx, id, req, "alice"), h.Running(ctx, id, req, "alice", "pve1", 120),
				h.Finished(ctx, id, StatusSucceeded, "", nil, false))
		}, StatusSucceeded},
		{"queued after finish", func(id string) error {
			return firstErr(h.Queued(ctx, id, req, "worker"), h.Running(ctx, id, req, "alice", "pve1", 120),
				h.Finished(ctx, id, StatusSucceeded, "", nil, false), h.Queued(ctx, id, req, "alice"))
		}, StatusSucceeded},
		{"queued while running", func(id string) error {
			return firstErr(h.Queued(ctx, id, req, "worker"), h.Running(ctx, id, req, "alice", "pve1", 120),
				h.Queued(ctx, id, req, "alice"))
		}, StatusRunning},
		{"failed before running, then late queued", func(id string) error {
			return firstErr(h.Queued(ctx, id, req, "worker"), h.Finished(ctx, id, StatusFailed, "boom", nil, false),
				h.Queued(ctx, id, req, "alice"))
		}, StatusFailed},
		{"running after finish is ignored", func(id string) error {
			return firstErr(h.Queued(ctx, id, req, "worker"), h.Finished(ctx, id, StatusFailed, "boom", nil, false),
				h.Running(ctx, id, req, "alice", "pve1", 120))
		}, StatusFailed},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := "job-" + itoa(i)
			if err := tt.calls(id); err != nil {
				t.Fatal(err)
			}
			list, err := h.List(ctx, 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range list {
				if d.JobID == id {
					if d.Status != tt.want {
						t.Errorf("status = %q, want %q", d.Status, tt.want)
					}
					return
				}
			}
			t.Fatalf("job %s not in history", id)
		})
	}
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
