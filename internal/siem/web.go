package siem

import (
	"errors"
	"io/fs"
	"net/http"
	"slices"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// maxCredentialLen bounds credential form values.
const maxCredentialLen = 8192

type module struct {
	m     *Manager
	creds *dbCredentials
}

func (mod *module) Name() string { return "siem" }

func (mod *module) Templates() fs.FS {
	sub, _ := fs.Sub(templatesFS, "templates")
	return sub
}

func (mod *module) Nav() []web.NavItem {
	return []web.NavItem{{Label: "SIEM", Path: "/settings/siem", Permission: rbac.SIEMManage, Order: 72}}
}

func (mod *module) Routes(rt *web.Router) {
	rt.HandleFunc("GET /settings/siem", rbac.SIEMManage, mod.page(rt))
	rt.HandleFunc("GET /settings/siem/status", rbac.SIEMManage, mod.status(rt))
	rt.HandleFunc("POST /settings/siem/{name}/credential", rbac.SIEMManage, mod.setCredential(rt))
	rt.HandleFunc("POST /settings/siem/{name}/test", rbac.SIEMManage, mod.test(rt))
}

type outputView struct {
	Status
	Fields []CredentialInfo
}

type pageData struct {
	Outputs []outputView
}

func (mod *module) statuses() []Status { return mod.m.Statuses() }

func (mod *module) page(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var d pageData
		for _, st := range mod.statuses() {
			ov := outputView{Status: st}
			if fields := CredentialFields(st.Type); len(fields) > 0 {
				info, err := mod.creds.Info(r.Context(), st.Name, fields)
				if err != nil {
					rt.Server().Logger().Error("siem credential info", "component", "siem", "err", err)
					rt.Server().Error(w, r, http.StatusInternalServerError, "Could not load SIEM credentials.")
					return
				}
				ov.Fields = info
			}
			d.Outputs = append(d.Outputs, ov)
		}
		rt.Render(w, r, "siem/siem.html", "SIEM forwarding", d)
	}
}

func (mod *module) status(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rt.Server().RenderPartial(w, r, "siem/siem.html", "siem-status-partial", mod.statuses())
	}
}

type resultData struct {
	OK      bool
	Message string
}

func (mod *module) respond(rt *web.Router, w http.ResponseWriter, r *http.Request, status int, res resultData) {
	if r.Header.Get("HX-Request") == "" {
		if !res.OK {
			rt.Server().Error(w, r, status, res.Message)
			return
		}
		http.Redirect(w, r, "/settings/siem", http.StatusSeeOther)
		return
	}
	// htmx swaps 2xx responses only; errors are shown in the same slot.
	rt.Server().RenderPartial(w, r, "siem/siem.html", "result", res)
}

func (mod *module) setCredential(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		cfg, ok := mod.m.Output(name)
		if !ok {
			rt.Server().Error(w, r, http.StatusNotFound, "Unknown SIEM output.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			mod.respond(rt, w, r, http.StatusBadRequest, resultData{Message: "Invalid form."})
			return
		}
		field := r.PostFormValue("field")
		if !slices.Contains(CredentialFields(cfg.Type), field) {
			mod.respond(rt, w, r, http.StatusBadRequest, resultData{Message: "This output does not accept that credential."})
			return
		}
		value := strings.TrimSpace(r.PostFormValue("value"))
		clear := r.PostFormValue("clear") == "1"
		if len(value) > maxCredentialLen || (value == "" && !clear) {
			mod.respond(rt, w, r, http.StatusBadRequest, resultData{Message: "Enter a value (or use Clear)."})
			return
		}
		if clear {
			value = ""
		}
		action := "siem.credential.set"
		if clear {
			action = "siem.credential.clear"
		}
		ev := auditlog.RequestEvent(r, action, "siem:"+name+":"+field, audit.OutcomeSuccess)
		actor := ev.Actor
		if err := mod.creds.Set(r.Context(), name, field, value, actor); err != nil {
			ev.Outcome, ev.Reason = audit.OutcomeFailure, "store failed"
			_ = rt.Server().Audit().Record(r.Context(), ev)
			rt.Server().Logger().Error("siem store credential", "component", "siem", "output", name, "err", err)
			mod.respond(rt, w, r, http.StatusInternalServerError, resultData{Message: "Could not store the credential."})
			return
		}
		_ = rt.Server().Audit().Record(r.Context(), ev)
		msg := "Saved " + field + " (sealed)."
		if clear {
			msg = "Cleared " + field + "."
		}
		mod.respond(rt, w, r, http.StatusOK, resultData{OK: true, Message: msg})
	}
}

func (mod *module) test(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := mod.m.Output(name); !ok {
			rt.Server().Error(w, r, http.StatusNotFound, "Unknown SIEM output.")
			return
		}
		ev := auditlog.RequestEvent(r, "siem.test", "siem:"+name, audit.OutcomeSuccess)
		err := mod.m.Test(r.Context(), name, ev.Actor)
		res := resultData{OK: err == nil, Message: "Test event delivered."}
		switch {
		case errors.Is(err, ErrUnknownOutput):
			ev.Outcome, ev.Reason = audit.OutcomeFailure, "output disabled"
			res.Message = "Output is disabled."
		case err != nil:
			ev.Outcome, ev.Reason = audit.OutcomeFailure, err.Error()
			res.Message = "Delivery failed: " + err.Error()
		}
		_ = rt.Server().Audit().Record(r.Context(), ev)
		mod.respond(rt, w, r, http.StatusBadGateway, res)
	}
}
