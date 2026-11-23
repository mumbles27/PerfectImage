package proxmox

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// StylesheetPath is the shared form stylesheet served by this module (also
// used by the deploy pages).
const StylesheetPath = "/proxmox/static/forms.css"

type module struct {
	reg   *Registry
	audit audit.Recorder
	log   *slog.Logger
	rt    *web.Router
}

func newModule(reg *Registry, rec audit.Recorder, log *slog.Logger) *module {
	if rec == nil {
		rec = audit.NopRecorder{}
	}
	return &module{reg: reg, audit: rec, log: log.With("component", "proxmox.web")}
}

func (m *module) Name() string { return "proxmox" }

func (m *module) Templates() fs.FS {
	sub, _ := fs.Sub(templatesFS, "templates")
	return sub
}

func (m *module) Nav() []web.NavItem {
	return []web.NavItem{{Label: "Proxmox", Path: "/settings/proxmox", Permission: rbac.ProxmoxManage, Order: 75}}
}

func (m *module) Routes(rt *web.Router) {
	m.rt = rt
	static, _ := fs.Sub(staticFS, "static")
	rt.HandlePublic("GET /proxmox/static/", http.StripPrefix("/proxmox/static/", http.FileServerFS(static)))
	rt.HandleFunc("GET /settings/proxmox", rbac.ProxmoxManage, m.list)
	rt.HandleFunc("POST /settings/proxmox", rbac.ProxmoxManage, m.create)
	rt.HandleFunc("POST /settings/proxmox/test", rbac.ProxmoxManage, m.testForm)
	rt.HandleFunc("GET /settings/proxmox/{id}", rbac.ProxmoxManage, m.edit)
	rt.HandleFunc("POST /settings/proxmox/{id}", rbac.ProxmoxManage, m.update)
	rt.HandleFunc("POST /settings/proxmox/{id}/delete", rbac.ProxmoxManage, m.remove)
	rt.HandleFunc("POST /settings/proxmox/{id}/test", rbac.ProxmoxManage, m.testStored)
}

// formView is the cluster form. The secret is never echoed back.
type formView struct {
	ID       int64
	In       ClusterInput
	HasToken bool
	Error    string
}

type listView struct {
	Clusters []*Cluster
	Form     formView
	Notice   string
}

type testView struct {
	OK          bool
	Version     string
	Nodes       []string
	Message     string
	Fingerprint string
}

func (m *module) list(w http.ResponseWriter, r *http.Request) {
	m.renderList(w, r, http.StatusOK, formView{}, r.URL.Query().Get("notice"))
}

func (m *module) renderList(w http.ResponseWriter, r *http.Request, status int, f formView, notice string) {
	cs, err := m.reg.Clusters(r.Context())
	if err != nil {
		m.log.Error("list clusters", "err", err)
		m.rt.Server().Error(w, r, http.StatusInternalServerError, "Could not load clusters.")
		return
	}
	m.rt.Server().Render(w, r, status, "proxmox/clusters.html", "Proxmox clusters",
		listView{Clusters: cs, Form: f, Notice: notice})
}

func formInput(r *http.Request) ClusterInput {
	return ClusterInput{
		Name:               r.PostFormValue("name"),
		Endpoint:           r.PostFormValue("endpoint"),
		TokenID:            r.PostFormValue("token_id"),
		Secret:             r.PostFormValue("token_secret"),
		CAPEM:              r.PostFormValue("ca_pem"),
		CAFile:             r.PostFormValue("ca_file"),
		Fingerprint:        r.PostFormValue("fingerprint"),
		InsecureSkipVerify: r.PostFormValue("insecure_skip_verify") == "1",
		DefaultNode:        r.PostFormValue("default_node"),
		DefaultStorage:     r.PostFormValue("default_storage"),
		DefaultBridge:      r.PostFormValue("default_bridge"),
		DefaultPool:        r.PostFormValue("default_pool"),
	}
}

func redacted(in ClusterInput) ClusterInput { in.Secret = ""; return in }

func (m *module) create(w http.ResponseWriter, r *http.Request) {
	in := formInput(r)
	c, err := m.reg.Store().Create(r.Context(), in)
	if err != nil {
		m.record(r, "proxmox.cluster.create", "cluster:"+strings.TrimSpace(in.Name), err, nil)
		m.renderList(w, r, http.StatusUnprocessableEntity, formView{In: redacted(in), Error: err.Error()}, "")
		return
	}
	m.record(r, "proxmox.cluster.create", "cluster:"+c.Name, nil, clusterDetails(c))
	if c.InsecureSkipVerify && c.Fingerprint == "" {
		m.log.Warn("proxmox cluster saved with TLS verification disabled", "cluster", c.Name)
	}
	http.Redirect(w, r, "/settings/proxmox?notice=Cluster+"+c.Name+"+added", http.StatusSeeOther)
}

func (m *module) cluster(w http.ResponseWriter, r *http.Request) (*Cluster, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		m.rt.Server().Error(w, r, http.StatusNotFound, "Cluster not found.")
		return nil, false
	}
	c, err := m.reg.Store().Get(r.Context(), id)
	if errors.Is(err, ErrClusterNotFound) {
		m.rt.Server().Error(w, r, http.StatusNotFound, "Cluster not found.")
		return nil, false
	}
	if err != nil {
		m.log.Error("get cluster", "err", err)
		m.rt.Server().Error(w, r, http.StatusInternalServerError, "Could not load cluster.")
		return nil, false
	}
	return c, true
}

func inputOf(c *Cluster) ClusterInput {
	return ClusterInput{Name: c.Name, Endpoint: c.Endpoint, TokenID: c.TokenID, CAPEM: c.CAPEM, CAFile: c.CAFile,
		Fingerprint: c.Fingerprint, InsecureSkipVerify: c.InsecureSkipVerify, DefaultNode: c.DefaultNode,
		DefaultStorage: c.DefaultStorage, DefaultBridge: c.DefaultBridge, DefaultPool: c.DefaultPool}
}

func (m *module) edit(w http.ResponseWriter, r *http.Request) {
	c, ok := m.cluster(w, r)
	if !ok {
		return
	}
	m.rt.Render(w, r, "proxmox/cluster_edit.html", "Edit "+c.Name,
		formView{ID: c.ID, In: inputOf(c), HasToken: c.HasSecret})
}

func (m *module) update(w http.ResponseWriter, r *http.Request) {
	c, ok := m.cluster(w, r)
	if !ok {
		return
	}
	in := formInput(r)
	nc, err := m.reg.Store().Update(r.Context(), c.ID, in)
	if err != nil {
		m.record(r, "proxmox.cluster.update", "cluster:"+c.Name, err, nil)
		m.rt.Server().Render(w, r, http.StatusUnprocessableEntity, "proxmox/cluster_edit.html", "Edit "+c.Name,
			formView{ID: c.ID, In: redacted(in), HasToken: c.HasSecret, Error: err.Error()})
		return
	}
	d := clusterDetails(nc)
	d["token_rotated"] = strings.TrimSpace(in.Secret) != ""
	m.record(r, "proxmox.cluster.update", "cluster:"+nc.Name, nil, d)
	http.Redirect(w, r, "/settings/proxmox?notice=Cluster+"+nc.Name+"+saved", http.StatusSeeOther)
}

func (m *module) remove(w http.ResponseWriter, r *http.Request) {
	c, ok := m.cluster(w, r)
	if !ok {
		return
	}
	err := m.reg.Store().Delete(r.Context(), c.ID)
	m.record(r, "proxmox.cluster.delete", "cluster:"+c.Name, err, nil)
	if err != nil {
		m.log.Error("delete cluster", "err", err)
		m.rt.Server().Error(w, r, http.StatusInternalServerError, "Could not delete cluster.")
		return
	}
	m.reg.Forget(c.ID)
	http.Redirect(w, r, "/settings/proxmox?notice=Cluster+"+c.Name+"+deleted", http.StatusSeeOther)
}

// testForm tests unsaved form values (used by the add/edit forms). With an
// "id" field and an empty secret, the stored secret is used.
func (m *module) testForm(w http.ResponseWriter, r *http.Request) {
	in := formInput(r)
	var existing *Cluster
	if id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64); err == nil && id > 0 {
		if existing, err = m.reg.Store().Get(r.Context(), id); err != nil {
			existing = nil
		}
	}
	cl, err := m.reg.NewClientFromInput(in, existing)
	if err != nil {
		m.renderTest(w, r, "cluster:"+strings.TrimSpace(in.Name), testView{Message: err.Error()}, err)
		return
	}
	v, err := testConnection(r.Context(), cl)
	m.renderTest(w, r, "cluster:"+strings.TrimSpace(in.Name), v, err)
}

func (m *module) testStored(w http.ResponseWriter, r *http.Request) {
	c, ok := m.cluster(w, r)
	if !ok {
		return
	}
	cl, err := m.reg.ClientFor(c)
	if err != nil {
		m.renderTest(w, r, "cluster:"+c.Name, testView{Message: err.Error()}, err)
		return
	}
	v, err := testConnection(r.Context(), cl)
	m.renderTest(w, r, "cluster:"+c.Name, v, err)
}

func (m *module) renderTest(w http.ResponseWriter, r *http.Request, target string, v testView, err error) {
	m.record(r, "proxmox.cluster.test", target, err, nil)
	m.rt.Server().RenderPartial(w, r, "proxmox/clusters.html", "test-result", v)
}

// testConnection calls /version and /nodes.
func testConnection(ctx context.Context, cl *Client) (testView, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ver, err := cl.Version(ctx)
	if err != nil {
		return testView{Message: describe(err), Fingerprint: pinHint(err)}, err
	}
	v := testView{OK: true, Version: ver.Version + " (" + ver.Release + ")"}
	nodes, err := cl.Nodes(ctx)
	if err != nil {
		v.Message = "Connected, but listing nodes failed: " + describe(err)
		return v, nil
	}
	for _, n := range nodes {
		v.Nodes = append(v.Nodes, n.Node+" ("+n.Status+")")
	}
	return v, nil
}

func describe(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "Authentication failed: check the token id and secret. (" + err.Error() + ")"
	case errors.Is(err, ErrForbidden):
		return "The token lacks a privilege (see docs/proxmox.md). (" + err.Error() + ")"
	case errors.Is(err, ErrTLSPin):
		return "The server certificate does not match the pinned fingerprint. (" + err.Error() + ")"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "Timed out connecting to the endpoint. (" + err.Error() + ")"
	}
	return err.Error()
}

// pinHint extracts the presented fingerprint from a pin mismatch.
func pinHint(err error) string {
	if !errors.Is(err, ErrTLSPin) {
		return ""
	}
	s := err.Error()
	if i := strings.Index(s, "server presented "); i >= 0 {
		return strings.TrimSuffix(s[i+len("server presented "):], ")")
	}
	return ""
}

func clusterDetails(c *Cluster) map[string]any {
	return map[string]any{"endpoint": c.Endpoint, "token_id": c.TokenID, "tls": c.TLSMode()}
}

func (m *module) record(r *http.Request, action, target string, err error, details map[string]any) {
	p := auth.PrincipalFrom(r.Context())
	ev := audit.Event{Action: action, Target: target, Outcome: audit.OutcomeSuccess,
		SourceIP: remoteIP(r), UserAgent: r.UserAgent(), RequestID: web.RequestIDFrom(r.Context()), Details: details}
	if p != nil {
		ev.ActorID, ev.Actor = p.ID, p.Username
	}
	if err != nil {
		ev.Outcome, ev.Reason = audit.OutcomeFailure, truncate(err.Error(), 300)
	}
	if rerr := m.audit.Record(r.Context(), ev); rerr != nil {
		m.log.Warn("audit record failed", "action", action, "err", rerr)
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
