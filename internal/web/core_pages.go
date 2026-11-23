package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// coreModule provides the Dashboard and Jobs pages. It is also the reference
// implementation of Module for domain agents.
type coreModule struct {
	s *Server
}

func newCoreModule(s *Server) *coreModule { return &coreModule{s: s} }

func (m *coreModule) Name() string { return "core" }

func (m *coreModule) Nav() []NavItem { return nil } // core sections come from coreNav

func (m *coreModule) Routes(rt *Router) {
	rt.HandleFunc("GET /{$}", "", m.dashboard)
	if m.s.opts.Jobs == nil {
		return
	}
	rt.HandleFunc("GET /jobs", rbac.JobsView, m.jobsList)
	rt.HandleFunc("GET /jobs/{id}", rbac.JobsView, m.jobDetail)
	rt.HandleFunc("GET /jobs/{id}/stream", rbac.JobsView, m.jobStream)
	rt.HandleFunc("POST /jobs/{id}/cancel", rbac.JobsCancel, m.jobCancel)
}

type dashboardData struct {
	Counts     map[string]int
	Recent     []*jobs.Job
	Types      []string
	CanViewJob bool
}

func (m *coreModule) dashboard(w http.ResponseWriter, r *http.Request) {
	d := dashboardData{Counts: map[string]int{}}
	p := auth.PrincipalFrom(r.Context())
	d.CanViewJob = m.s.authorizer().Authorize(r.Context(), p, rbac.JobsView) == nil
	if m.s.opts.Jobs != nil && d.CanViewJob {
		counts, err := m.s.opts.Jobs.Counts(r.Context())
		if err != nil {
			m.s.log.Error("dashboard counts", "err", err)
		}
		for k, v := range counts {
			d.Counts[string(k)] = v
		}
		if d.Recent, err = m.s.opts.Jobs.List(r.Context(), jobs.ListOptions{Limit: 10}); err != nil {
			m.s.log.Error("dashboard recent jobs", "err", err)
		}
		d.Types = m.s.opts.Jobs.Types()
	}
	m.s.Render(w, r, http.StatusOK, "core/dashboard.html", "Dashboard", d)
}

type jobsListData struct {
	Jobs     []*jobs.Job
	Status   string
	Statuses []jobs.Status
}

func (m *coreModule) jobsList(w http.ResponseWriter, r *http.Request) {
	status := jobs.Status(r.URL.Query().Get("status"))
	switch status {
	case "", jobs.StatusQueued, jobs.StatusRunning, jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled:
	default:
		m.s.Error(w, r, http.StatusBadRequest, "Unknown status filter.")
		return
	}
	list, err := m.s.opts.Jobs.List(r.Context(), jobs.ListOptions{Status: status, Limit: 100})
	if err != nil {
		m.s.log.Error("list jobs", "err", err)
		m.s.Error(w, r, http.StatusInternalServerError, "Could not load jobs.")
		return
	}
	d := jobsListData{
		Jobs:   list,
		Status: string(status),
		Statuses: []jobs.Status{jobs.StatusQueued, jobs.StatusRunning, jobs.StatusSucceeded,
			jobs.StatusFailed, jobs.StatusCanceled},
	}
	if r.Header.Get("HX-Request") != "" {
		m.s.RenderPartial(w, r, "core/jobs.html", "jobs-table", d)
		return
	}
	m.s.Render(w, r, http.StatusOK, "core/jobs.html", "Jobs", d)
}

type jobDetailData struct {
	Job       *jobs.Job
	CanCancel bool
}

func (m *coreModule) jobDetail(w http.ResponseWriter, r *http.Request) {
	j, err := m.s.opts.Jobs.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, jobs.ErrNotFound) {
		m.s.Error(w, r, http.StatusNotFound, "Job not found.")
		return
	}
	if err != nil {
		m.s.log.Error("get job", "err", err)
		m.s.Error(w, r, http.StatusInternalServerError, "Could not load job.")
		return
	}
	p := auth.PrincipalFrom(r.Context())
	d := jobDetailData{
		Job:       j,
		CanCancel: !j.Status.Terminal() && m.s.authorizer().Authorize(r.Context(), p, rbac.JobsCancel) == nil,
	}
	m.s.Render(w, r, http.StatusOK, "core/job.html", "Job "+j.ID, d)
}

func (m *coreModule) jobCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := auth.PrincipalFrom(r.Context())
	err := m.s.opts.Jobs.Cancel(r.Context(), id)
	ev := audit.Event{
		ActorID: p.ID, Actor: p.Username, Action: "job.cancel", Target: "job:" + id,
		Outcome: audit.OutcomeSuccess, SourceIP: clientIP(r), UserAgent: r.UserAgent(),
		RequestID: RequestIDFrom(r.Context()),
	}
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		m.s.Error(w, r, http.StatusNotFound, "Job not found.")
		return
	case errors.Is(err, jobs.ErrNotCancelable):
		// Already finished: fall through to redirect, nothing to cancel.
		ev.Outcome, ev.Reason = audit.OutcomeFailure, "already finished"
	case err != nil:
		m.s.log.Error("cancel job", "job_id", id, "err", err)
		ev.Outcome, ev.Reason = audit.OutcomeFailure, "internal error"
		_ = m.s.opts.Audit.Record(r.Context(), ev)
		m.s.Error(w, r, http.StatusInternalServerError, "Could not cancel job.")
		return
	}
	_ = m.s.opts.Audit.Record(r.Context(), ev)
	http.Redirect(w, r, "/jobs/"+id, http.StatusSeeOther)
}

// jobStream streams job log lines and status changes as Server-Sent Events.
//
// Events: "log" (data: {"id","time","line"}), "status" (data: status string),
// "done" (job reached a terminal state; client should close). The SSE id is
// the last log line ID so reconnects resume via Last-Event-ID.
func (m *coreModule) jobStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	mgr := m.s.opts.Jobs
	if _, err := mgr.Get(ctx, id); err != nil {
		if errors.Is(err, jobs.ErrNotFound) {
			http.Error(w, "job not found", http.StatusNotFound)
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	var lastID int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		lastID, _ = strconv.ParseInt(v, 10, 64)
	}

	events, unsub := mgr.Subscribe(id)
	defer unsub()

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	lastStatus := jobs.Status("")
	// sync drains new log lines from the store and emits status; it returns
	// true once the job is terminal and all lines have been sent.
	sync := func() (bool, error) {
		for {
			lines, err := mgr.Logs(ctx, id, lastID, 500)
			if err != nil {
				return false, err
			}
			for _, l := range lines {
				b, _ := json.Marshal(map[string]any{"id": l.ID, "time": l.Time.Format(time.RFC3339Nano), "line": l.Line})
				if _, err := fmt.Fprintf(w, "id: %d\nevent: log\ndata: %s\n\n", l.ID, b); err != nil {
					return false, err
				}
				lastID = l.ID
			}
			if len(lines) < 500 {
				break
			}
		}
		j, err := mgr.Get(ctx, id)
		if err != nil {
			return false, err
		}
		if j.Status != lastStatus {
			lastStatus = j.Status
			if _, err := fmt.Fprintf(w, "event: status\ndata: %s\n\n", j.Status); err != nil {
				return false, err
			}
		}
		if j.Status.Terminal() {
			_, err := fmt.Fprint(w, "event: done\ndata: {}\n\n")
			_ = rc.Flush()
			return true, err
		}
		return false, rc.Flush()
	}

	if done, err := sync(); done || err != nil {
		return
	}
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
		}
		if done, err := sync(); done || err != nil {
			return
		}
	}
}
