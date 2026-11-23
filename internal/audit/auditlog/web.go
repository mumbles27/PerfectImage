package auditlog

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

const pageSize = 50

// verifyCacheTTL bounds how often a full chain verification runs for the UI.
const verifyCacheTTL = 30 * time.Second

type module struct {
	st *Store

	mu         sync.Mutex
	lastVerify *VerifyResult
	lastErr    error
	lastBroken bool
}

func (m *module) Name() string { return "audit" }

func (m *module) Templates() fs.FS {
	sub, _ := fs.Sub(templatesFS, "templates")
	return sub
}

func (m *module) Nav() []web.NavItem {
	return []web.NavItem{{Label: "Audit", Path: "/audit", Permission: rbac.AuditView}}
}

func (m *module) Routes(rt *web.Router) {
	rt.HandleFunc("GET /audit", rbac.AuditView, m.list(rt))
	rt.HandleFunc("GET /audit/verify", rbac.AuditView, m.verify(rt))
	rt.HandleFunc("GET /audit/export", rbac.AuditView, m.export(rt))
	rt.HandleFunc("GET /audit/metrics", rbac.AuditView, m.metrics)
	rt.HandlePublic("GET "+StylesheetPath, http.HandlerFunc(serveCSS))
}

func serveCSS(w http.ResponseWriter, r *http.Request) {
	b, _ := staticFS.ReadFile("static/ops.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

type filterForm struct {
	From, To, Actor, Action, Outcome, Target string
}

func (f filterForm) values() url.Values {
	v := url.Values{}
	for k, s := range map[string]string{"from": f.From, "to": f.To, "actor": f.Actor,
		"action": f.Action, "outcome": f.Outcome, "target": f.Target} {
		if s != "" {
			v.Set(k, s)
		}
	}
	return v
}

// parseTime accepts RFC 3339 or the HTML datetime-local format (server-local time).
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q", s)
}

func parseFilter(r *http.Request) (Filter, filterForm, error) {
	q := r.URL.Query()
	ff := filterForm{
		From: q.Get("from"), To: q.Get("to"), Actor: strings.TrimSpace(q.Get("actor")),
		Action: strings.TrimSpace(q.Get("action")), Outcome: q.Get("outcome"), Target: strings.TrimSpace(q.Get("target")),
	}
	f := Filter{Actor: ff.Actor, Action: ff.Action, Target: ff.Target}
	switch audit.Outcome(ff.Outcome) {
	case "", audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeDenied:
		f.Outcome = ff.Outcome
	default:
		return f, ff, fmt.Errorf("invalid outcome %q", ff.Outcome)
	}
	var err error
	if f.From, err = parseTime(ff.From); err != nil {
		return f, ff, err
	}
	if f.To, err = parseTime(ff.To); err != nil {
		return f, ff, err
	}
	return f, ff, nil
}

type row struct {
	Entry
	DetailsJSON string
}

type listData struct {
	Filter     filterForm
	Outcomes   []audit.Outcome
	Rows       []row
	Total      int
	Page       int
	Pages      int
	PrevURL    string
	NextURL    string
	ExportCSV  string
	ExportJSON string
	Metrics    Metrics
}

func (m *module) list(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, ff, err := parseFilter(r)
		if err != nil {
			rt.Server().Error(w, r, http.StatusBadRequest, err.Error())
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		f.Limit, f.Offset = pageSize, (page-1)*pageSize
		entries, total, err := m.st.Query(r.Context(), f)
		if err != nil {
			rt.Server().Logger().Error("audit query", "err", err)
			rt.Server().Error(w, r, http.StatusInternalServerError, "Could not load audit events.")
			return
		}
		d := listData{
			Filter: ff, Total: total, Page: page, Pages: max(1, (total+pageSize-1)/pageSize),
			Outcomes: []audit.Outcome{audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeDenied},
			Metrics:  m.st.Metrics(),
		}
		for _, e := range entries {
			rw := row{Entry: e}
			if len(e.Details) > 0 {
				b, _ := json.MarshalIndent(e.Details, "", "  ")
				rw.DetailsJSON = string(b)
			}
			d.Rows = append(d.Rows, rw)
		}
		link := func(p int) string {
			v := ff.values()
			v.Set("page", strconv.Itoa(p))
			return "/audit?" + v.Encode()
		}
		if page > 1 {
			d.PrevURL = link(page - 1)
		}
		if page < d.Pages {
			d.NextURL = link(page + 1)
		}
		ev := ff.values()
		ev.Set("format", "csv")
		d.ExportCSV = "/audit/export?" + ev.Encode()
		ev.Set("format", "json")
		d.ExportJSON = "/audit/export?" + ev.Encode()
		rt.Render(w, r, "audit/audit.html", "Audit", d)
	}
}

// cachedVerify runs Verify at most once per verifyCacheTTL (or when force).
func (m *module) cachedVerify(ctx context.Context, force bool) (*VerifyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !force && m.lastVerify != nil && time.Since(m.lastVerify.VerifiedAt) < verifyCacheTTL {
		return m.lastVerify, m.lastErr
	}
	res, err := m.st.Verify(ctx)
	m.lastVerify, m.lastErr = &res, err
	if err == nil {
		if !res.OK && !m.lastBroken {
			m.st.log.Error("audit hash chain verification failed", "seq", res.BrokenSeq, "problem", res.Problem)
			_ = m.st.Record(ctx, audit.Event{Actor: "system", Action: "audit.chain.broken",
				Outcome: audit.OutcomeFailure, Target: fmt.Sprintf("audit:%d", res.BrokenSeq), Reason: res.Problem})
		}
		m.lastBroken = !res.OK
	}
	return &res, err
}

func (m *module) verify(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := m.cachedVerify(r.Context(), r.URL.Query().Get("force") == "1")
		if err != nil {
			rt.Server().Logger().Error("audit verify", "err", err)
		}
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(res)
			return
		}
		rt.Server().RenderPartial(w, r, "audit/audit.html", "verify-badge", map[string]any{"Result": res, "Err": err})
	}
}

func (m *module) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(m.st.Metrics())
}

// csvSafe neutralizes spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (m *module) export(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, _, err := parseFilter(r)
		if err != nil {
			rt.Server().Error(w, r, http.StatusBadRequest, err.Error())
			return
		}
		format := r.URL.Query().Get("format")
		if format != "csv" && format != "json" {
			rt.Server().Error(w, r, http.StatusBadRequest, "format must be csv or json")
			return
		}
		ev := RequestEvent(r, "audit.export", "audit_events", audit.OutcomeSuccess)
		ev.Details = map[string]any{"format": format, "filter": f.Params()}
		if err := m.st.Record(r.Context(), ev); err != nil {
			// The export itself must be audited; refuse if that fails.
			rt.Server().Error(w, r, http.StatusServiceUnavailable, "Audit log unavailable; export refused.")
			return
		}
		// Make sure everything recorded so far (including this export) is included.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		_ = m.st.Flush(ctx)
		cancel()

		ext := map[string]string{"csv": ".csv", "json": ".ndjson"}[format]
		name := "audit-" + time.Now().UTC().Format("20060102T150405Z") + ext
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "no-store")
		var streamErr error
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			cw := csv.NewWriter(w)
			_ = cw.Write([]string{"seq", "id", "time", "actor_id", "actor", "action", "target", "outcome",
				"reason", "source_ip", "user_agent", "request_id", "details", "prev_hash", "hash"})
			streamErr = m.st.Each(r.Context(), f, func(e Entry) error {
				return cw.Write([]string{strconv.FormatInt(e.Seq, 10), e.ID, e.Time.Format(time.RFC3339Nano),
					csvSafe(e.ActorID), csvSafe(e.Actor), csvSafe(e.Action), csvSafe(e.Target), string(e.Outcome),
					csvSafe(e.Reason), csvSafe(e.SourceIP), csvSafe(e.UserAgent), csvSafe(e.RequestID),
					csvSafe(e.rawDetails), e.PrevHash, e.Hash})
			})
			cw.Flush()
		} else {
			w.Header().Set("Content-Type", "application/x-ndjson")
			enc := json.NewEncoder(w)
			streamErr = m.st.Each(r.Context(), f, func(e Entry) error { return enc.Encode(e) })
		}
		if streamErr != nil {
			rt.Server().Logger().Error("audit export", "err", streamErr)
		}
	}
}
