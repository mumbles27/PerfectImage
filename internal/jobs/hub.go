package jobs

import "sync"

// EventKind distinguishes hub events.
type EventKind string

// Event kinds.
const (
	EventLog    EventKind = "log"
	EventStatus EventKind = "status"
)

// Event is published to subscribers when a job logs a line or changes state.
// Delivery is best-effort (slow subscribers drop events); consumers that need
// completeness should treat events as a wake-up and read from the store
// (Manager.Logs with afterID), as the SSE handler does.
type Event struct {
	Kind   EventKind
	JobID  string
	Line   *LogLine // EventLog
	Status Status   // EventStatus
}

// Hub is an in-process pub/sub for job events.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan Event]struct{} // jobID ("" = all jobs) -> subscribers
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[string]map[chan Event]struct{}{}} }

// Subscribe returns a channel of events for jobID ("" for all jobs) and a
// cancel function that must be called to release it.
func (h *Hub) Subscribe(jobID string) (<-chan Event, func()) {
	ch := make(chan Event, 256)
	h.mu.Lock()
	if h.subs[jobID] == nil {
		h.subs[jobID] = map[chan Event]struct{}{}
	}
	h.subs[jobID][ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs[jobID], ch)
			if len(h.subs[jobID]) == 0 {
				delete(h.subs, jobID)
			}
			h.mu.Unlock()
			close(ch)
		})
	}
}

// Publish delivers e to subscribers of e.JobID and of all jobs without blocking.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, key := range []string{e.JobID, ""} {
		for ch := range h.subs[key] {
			select {
			case ch <- e:
			default: // subscriber is slow; drop
			}
		}
	}
}
