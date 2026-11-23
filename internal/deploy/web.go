package deploy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// Enqueuer is the subset of *jobs.Manager used by the wizard.
type Enqueuer interface {
	Enqueue(ctx context.Context, typ string, payload any, createdBy string) (string, error)
}

type historyLister interface {
	History
	List(ctx context.Context, limit int) ([]Deployment, error)
}

type module struct {
	clients ClientSource
	sealer  secrets.Sealer
	jobs    Enqueuer
	history historyLister
	audit   audit.Recorder
	log     *slog.Logger
	rt      *web.Router
}

func (m *module) Name() string { return "deploy" }

func (m *module) Templates() fs.FS {
	sub, _ := fs.Sub(templatesFS, "templates")
	return sub
}

func (m *module) Nav() []web.NavItem {
	return []web.NavItem{{Label: "Deploy", Path: "/deploy", Permission: rbac.DeployView}}
}

func (m *module) Routes(rt *web.Router) {
	m.rt = rt
	// GET /deploy is reachable with deploy.view so the Deploy nav entry works
	// for viewers; the wizard itself requires deploy.run (else redirect).
	rt.HandleFunc("GET /deploy", rbac.DeployView, m.wizard)
	rt.HandleFunc("POST /deploy", rbac.DeployRun, m.submit)
	rt.HandleFunc("GET /deploy/options", rbac.DeployRun, m.options)
	rt.HandleFunc("GET /deploy/osfields", rbac.DeployRun, m.osfields)
	rt.HandleFunc("GET /deploy/templates", rbac.DeployView, m.templates)
	rt.HandleFunc("POST /deploy/templates/delete", rbac.ImagesBuild, m.deleteTemplate)
	rt.HandleFunc("GET /deploy/history", rbac.DeployView, m.historyPage)
}

func (m *module) can(r *http.Request, perm rbac.Permission) bool {
	p := auth.PrincipalFrom(r.Context())
	return p != nil && m.rt.Server().Authorizer().Authorize(r.Context(), p, perm) == nil
}

// --- wizard ---

// formValues are the non-secret wizard inputs, kept for re-rendering.
type formValues struct {
	Cluster, Template, Node, Storage, Pool, Bridge, VLAN string
	Name, VMID, Cores, MemoryMB, DiskGB                  string
	LinkedClone, Cleanup                                 bool
	IPMode, IPCIDR, Gateway, DNS, SearchDomain           string
	CIUser, SSHKeys                                      string
	Hostname, Domain, DomainUser, DomainOU               string
	Apps                                                 []string
}

func (f formValues) HasApp(id string) bool {
	for _, a := range f.Apps {
		if a == id {
			return true
		}
	}
	return false
}

type tplOption struct {
	Value string // node/vmid
	Label string
	PI    bool
}

type optionsView struct {
	Cluster   string
	Templates []tplOption
	Nodes     []string
	Storages  []string
	Pools     []string
	Bridges   []string
	Form      formValues
	Error     string
	ClearOS   bool
}

type osView struct {
	OS           string
	TemplateName string
	HasCloudInit bool
	Apps         []AppInfo
	AppsError    string
	Form         formValues
	Error        string
}

type wizardView struct {
	Clusters []string
	Form     formValues
	Options  *optionsView
	OSFields *osView
	Errors   []string
}

func defaultForm() formValues {
	return formValues{Cores: "2", MemoryMB: "2048", IPMode: IPDHCP, Cleanup: true}
}

func (m *module) wizard(w http.ResponseWriter, r *http.Request) {
	if !m.can(r, rbac.DeployRun) {
		http.Redirect(w, r, "/deploy/templates", http.StatusSeeOther)
		return
	}
	f := defaultForm()
	f.Cluster = r.URL.Query().Get("cluster")
	m.renderWizard(w, r, http.StatusOK, f, nil)
}

func (m *module) renderWizard(w http.ResponseWriter, r *http.Request, status int, f formValues, errs []string) {
	ctx := r.Context()
	names, err := m.clients.ClusterNames(ctx)
	if err != nil {
		m.log.Error("list clusters", "err", err)
		m.rt.Server().Error(w, r, http.StatusInternalServerError, "Could not load clusters.")
		return
	}
	if f.Cluster == "" && len(names) == 1 {
		f.Cluster = names[0]
	}
	v := wizardView{Clusters: names, Form: f, Errors: errs}
	if f.Cluster != "" {
		o := m.buildOptions(ctx, f)
		v.Options = &o
		if f.Template != "" {
			os := m.buildOS(ctx, f)
			v.OSFields = &os
		}
	}
	m.rt.Server().Render(w, r, status, "deploy/wizard.html", "Deploy VM", v)
}

func (m *module) options(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := defaultForm()
	f.Cluster, f.Template, f.Node = q.Get("cluster"), q.Get("template"), q.Get("node")
	o := m.buildOptions(r.Context(), f)
	o.ClearOS = f.Template == ""
	m.rt.Server().RenderPartial(w, r, "deploy/wizard.html", "options", o)
}

func (m *module) osfields(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := defaultForm()
	f.Cluster, f.Template = q.Get("cluster"), q.Get("template")
	m.rt.Server().RenderPartial(w, r, "deploy/wizard.html", "osfields", m.buildOS(r.Context(), f))
}

func (m *module) buildOptions(ctx context.Context, f formValues) optionsView {
	o := optionsView{Cluster: f.Cluster, Form: f}
	if f.Cluster == "" {
		return o
	}
	cl, err := m.clients.Cluster(ctx, f.Cluster)
	if err != nil {
		o.Error = "Unknown cluster."
		return o
	}
	c, err := m.clients.Client(ctx, f.Cluster)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tpls, err := c.Templates(ctx)
	if err != nil {
		o.Error = "Could not list templates: " + err.Error()
		return o
	}
	sort.Slice(tpls, func(i, j int) bool { return tpls[i].Name < tpls[j].Name })
	for _, t := range tpls {
		pi := hasTag(t.TagList(), TagTemplate)
		o.Templates = append(o.Templates, tplOption{
			Value: fmt.Sprintf("%s/%d", t.Node, t.VMID),
			Label: fmt.Sprintf("%s (%d on %s)", t.Name, t.VMID, t.Node),
			PI:    pi,
		})
	}
	nodes, err := c.Nodes(ctx)
	if err != nil {
		o.Error = "Could not list nodes: " + err.Error()
		return o
	}
	for _, n := range nodes {
		if n.Status == "" || n.Status == "online" {
			o.Nodes = append(o.Nodes, n.Node)
		}
	}
	sort.Strings(o.Nodes)
	if o.Form.Node == "" {
		o.Form.Node = cl.DefaultNode
	}
	if o.Form.Node == "" && len(o.Nodes) > 0 {
		o.Form.Node = o.Nodes[0]
	}
	if o.Form.Storage == "" {
		o.Form.Storage = cl.DefaultStorage
	}
	if o.Form.Bridge == "" {
		o.Form.Bridge = cl.DefaultBridge
	}
	if o.Form.Pool == "" {
		o.Form.Pool = cl.DefaultPool
	}
	if o.Form.Node != "" {
		if sts, err := c.Storages(ctx, o.Form.Node, "images"); err == nil {
			for _, s := range sts {
				o.Storages = append(o.Storages, s.Storage)
			}
		}
		if nets, err := c.Networks(ctx, o.Form.Node, "any_bridge"); err == nil {
			for _, n := range nets {
				o.Bridges = append(o.Bridges, n.Iface)
			}
		}
	}
	if pools, err := c.Pools(ctx); err == nil {
		for _, p := range pools {
			o.Pools = append(o.Pools, p.PoolID)
		}
	}
	sort.Strings(o.Storages)
	sort.Strings(o.Bridges)
	sort.Strings(o.Pools)
	return o
}

func parseTemplateRef(s string) (string, int, error) {
	node, id, ok := strings.Cut(s, "/")
	vmid, err := strconv.Atoi(id)
	if !ok || node == "" || err != nil || vmid <= 0 {
		return "", 0, errors.New("choose a template")
	}
	return node, vmid, nil
}

// templateInfo reads the template config to determine OS and name.
func (m *module) templateInfo(ctx context.Context, cluster, ref string) (proxmox.VMConfig, string, int, error) {
	node, vmid, err := parseTemplateRef(ref)
	if err != nil {
		return nil, "", 0, err
	}
	c, err := m.clients.Client(ctx, cluster)
	if err != nil {
		return nil, "", 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cfg, err := c.VMConfig(ctx, node, vmid)
	if err != nil {
		return nil, "", 0, err
	}
	if !cfg.IsTemplate() {
		return nil, "", 0, fmt.Errorf("VM %d is not a template", vmid)
	}
	return cfg, node, vmid, nil
}

func (m *module) buildOS(ctx context.Context, f formValues) osView {
	v := osView{Form: f}
	cfg, _, _, err := m.templateInfo(ctx, f.Cluster, f.Template)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.OS, v.TemplateName, v.HasCloudInit = osOf(cfg), cfg.Get("name"), cfg.HasCloudInit()
	if l, ok := CurrentAppResolver().(AppLister); ok {
		apps, err := l.Apps(ctx, v.OS)
		if err != nil {
			v.AppsError = err.Error()
		}
		v.Apps = apps
	}
	return v
}

func formFrom(r *http.Request) formValues {
	pf := r.PostForm
	g := func(k string) string { return strings.TrimSpace(pf.Get(k)) }
	return formValues{
		Cluster: g("cluster"), Template: g("template"), Node: g("node"), Storage: g("storage"), Pool: g("pool"),
		Bridge: g("bridge"), VLAN: g("vlan"), Name: g("name"), VMID: g("vmid"), Cores: g("cores"),
		MemoryMB: g("memory_mb"), DiskGB: g("disk_gb"), LinkedClone: g("linked_clone") == "1", Cleanup: g("cleanup") == "1",
		IPMode: g("ip_mode"), IPCIDR: g("ip_cidr"), Gateway: g("gateway"), DNS: g("dns"), SearchDomain: g("search_domain"),
		CIUser: g("ci_user"), SSHKeys: pf.Get("ssh_keys"), Hostname: g("hostname"), Domain: g("domain"),
		DomainUser: g("domain_user"), DomainOU: g("domain_ou"), Apps: pf["apps"],
	}
}

func atoiField(errs *[]string, label, s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		*errs = append(*errs, label+" must be a number")
	}
	return n
}

// buildRequest converts the form into a sealed Request.
func (m *module) buildRequest(ctx context.Context, r *http.Request, f formValues) (Request, []string) {
	var errs []string
	req := Request{
		RequestID: NewRequestID(), Cluster: f.Cluster, Node: f.Node, Storage: f.Storage, Pool: f.Pool,
		Name: f.Name, LinkedClone: f.LinkedClone, Bridge: f.Bridge, IPMode: f.IPMode, IPCIDR: f.IPCIDR,
		Gateway: f.Gateway, SearchDomain: f.SearchDomain, CleanupOnFailure: f.Cleanup, Apps: f.Apps,
	}
	req.VMID = atoiField(&errs, "VMID", f.VMID)
	req.Cores = atoiField(&errs, "Cores", f.Cores)
	req.MemoryMB = atoiField(&errs, "Memory", f.MemoryMB)
	req.DiskGB = atoiField(&errs, "Disk", f.DiskGB)
	req.VLAN = atoiField(&errs, "VLAN", f.VLAN)
	req.DNSServers = strings.FieldsFunc(f.DNS, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })

	cfg, node, vmid, err := m.templateInfo(ctx, f.Cluster, f.Template)
	if err != nil {
		return req, append(errs, "Template: "+err.Error())
	}
	req.TemplateNode, req.TemplateVMID, req.TemplateName, req.OS = node, vmid, cfg.Get("name"), osOf(cfg)

	switch req.OS {
	case OSLinux:
		req.Linux.User = f.CIUser
		for _, line := range strings.Split(f.SSHKeys, "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				req.Linux.SSHKeys = append(req.Linux.SSHKeys, line)
			}
		}
	case OSWindows:
		req.Windows = WindowsOptions{Hostname: f.Hostname, Domain: f.Domain, DomainUser: f.DomainUser, DomainOU: f.DomainOU}
		pw, pw2 := r.PostFormValue("admin_password"), r.PostFormValue("admin_password_confirm")
		dpw := r.PostFormValue("domain_password")
		if pw != pw2 {
			errs = append(errs, "Administrator passwords do not match")
		}
		for field, v := range map[string]string{"Administrator password": pw, "Domain password": dpw} {
			if err := ValidatePassword(field, v); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if len(errs) == 0 {
			var err1, err2 error
			req.Windows.AdminPassword, err1 = SealSecret(m.sealer, req.RequestID, "admin_password", pw)
			req.Windows.DomainPassword, err2 = SealSecret(m.sealer, req.RequestID, "domain_password", dpw)
			if err := errors.Join(err1, err2); err != nil {
				m.log.Error("seal deploy secrets", "err", err)
				errs = append(errs, "Could not protect the passwords; try again.")
			}
		}
	}
	if err := req.Validate(); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			errs = append(errs, line)
		}
	}
	return req, errs
}

func (m *module) submit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		m.rt.Server().Error(w, r, http.StatusBadRequest, "Bad form.")
		return
	}
	f := formFrom(r)
	ctx := r.Context()
	p := auth.PrincipalFrom(ctx)
	req, errs := m.buildRequest(ctx, r, f)
	ev := m.event(r, "deploy.vm.request", "vm:"+f.Cluster+"/"+f.Name)
	ev.Details = map[string]any{"cluster": req.Cluster, "template_vmid": req.TemplateVMID, "name": req.Name,
		"node": req.Node, "os": req.OS, "apps": req.Apps}
	if len(errs) > 0 {
		ev.Outcome, ev.Reason = audit.OutcomeFailure, truncate(strings.Join(errs, "; "), 300)
		m.record(ctx, ev)
		m.renderWizard(w, r, http.StatusUnprocessableEntity, f, errs)
		return
	}
	id, err := m.jobs.Enqueue(ctx, JobType, req, p.Username)
	if err != nil {
		m.log.Error("enqueue deploy", "err", err)
		ev.Outcome, ev.Reason = audit.OutcomeFailure, "enqueue failed"
		m.record(ctx, ev)
		m.renderWizard(w, r, http.StatusInternalServerError, f, []string{"Could not queue the deployment."})
		return
	}
	if err := m.history.Queued(ctx, id, req, p.Username); err != nil {
		m.log.Warn("deploy history", "job_id", id, "err", err)
	}
	ev.Details["job_id"] = id
	m.record(ctx, ev)
	http.Redirect(w, r, "/jobs/"+id, http.StatusSeeOther)
}

// --- templates ---

type templateRow struct {
	Cluster  string
	Node     string
	VMID     int
	Name     string
	Tags     []string
	PI       bool
	Metadata [][2]string
}

type clusterError struct{ Cluster, Message string }

type templatesView struct {
	Rows      []templateRow
	Errors    []clusterError
	CanDelete bool
	CanDeploy bool
	Notice    string
	Error     string
}

var metaKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.\- ]{1,40}$`)

// ParseBuildMetadata extracts "key: value" / "key=value" lines from a
// template description (written by the packer module).
func ParseBuildMetadata(desc string) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(desc, "\n") {
		line = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line), "-*#"))
		i := strings.IndexAny(line, ":=")
		if i <= 0 {
			continue
		}
		k, v := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		if v == "" || !metaKeyRe.MatchString(k) {
			continue
		}
		out = append(out, [2]string{k, truncate(v, 200)})
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if strings.EqualFold(x, t) {
			return true
		}
	}
	return false
}

func (m *module) templates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := templatesView{CanDelete: m.can(r, rbac.ImagesBuild), CanDeploy: m.can(r, rbac.DeployRun),
		Notice: r.URL.Query().Get("notice"), Error: r.URL.Query().Get("error")}
	names, err := m.clients.ClusterNames(ctx)
	if err != nil {
		m.log.Error("list clusters", "err", err)
		m.rt.Server().Error(w, r, http.StatusInternalServerError, "Could not load clusters.")
		return
	}
	for _, name := range names {
		rows, err := m.clusterTemplates(ctx, name)
		if err != nil {
			v.Errors = append(v.Errors, clusterError{name, err.Error()})
			continue
		}
		v.Rows = append(v.Rows, rows...)
	}
	m.rt.Server().Render(w, r, http.StatusOK, "deploy/templates.html", "Templates", v)
}

func (m *module) clusterTemplates(ctx context.Context, name string) ([]templateRow, error) {
	c, err := m.clients.Client(ctx, name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tpls, err := c.Templates(ctx)
	if err != nil {
		return nil, err
	}
	var rows []templateRow
	for _, t := range tpls {
		row := templateRow{Cluster: name, Node: t.Node, VMID: int(t.VMID), Name: t.Name, Tags: t.TagList()}
		row.PI = hasTag(row.Tags, TagTemplate)
		if row.PI {
			if cfg, err := c.VMConfig(ctx, t.Node, int(t.VMID)); err == nil {
				row.Metadata = ParseBuildMetadata(cfg.Get("description"))
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].PI != rows[j].PI {
			return rows[i].PI
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, nil
}

func (m *module) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cluster, node := r.PostFormValue("cluster"), r.PostFormValue("node")
	vmid, _ := strconv.Atoi(r.PostFormValue("vmid"))
	ev := m.event(r, "image.template.delete", fmt.Sprintf("vm:%s/%d", cluster, vmid))
	ev.Details = map[string]any{"node": node}
	fail := func(msg string, err error) {
		ev.Outcome, ev.Reason = audit.OutcomeFailure, msg
		if err != nil {
			ev.Reason = truncate(msg+": "+err.Error(), 300)
		}
		m.record(ctx, ev)
		http.Redirect(w, r, "/deploy/templates?error="+url.QueryEscape(ev.Reason), http.StatusSeeOther)
	}
	if vmid <= 0 || node == "" || cluster == "" {
		fail("missing template reference", nil)
		return
	}
	c, err := m.clients.Client(ctx, cluster)
	if err != nil {
		fail("cluster unavailable", err)
		return
	}
	cfg, err := c.VMConfig(ctx, node, vmid)
	if err != nil {
		fail("could not read template", err)
		return
	}
	if !cfg.IsTemplate() {
		fail(fmt.Sprintf("VM %d is not a template; refusing to delete", vmid), nil)
		return
	}
	ev.Details["name"] = cfg.Get("name")
	upid, err := c.DeleteVM(ctx, node, vmid)
	if err == nil {
		err = waitTask(ctx, c, upid, 5*time.Minute)
	}
	if err != nil {
		fail("delete failed", err)
		return
	}
	m.record(ctx, ev)
	http.Redirect(w, r, "/deploy/templates?notice="+url.QueryEscape(fmt.Sprintf("Template %s (%d) deleted", cfg.Get("name"), vmid)),
		http.StatusSeeOther)
}

// --- history ---

func (m *module) historyPage(w http.ResponseWriter, r *http.Request) {
	list, err := m.history.List(r.Context(), 200)
	if err != nil {
		m.log.Error("deploy history", "err", err)
		m.rt.Server().Error(w, r, http.StatusInternalServerError, "Could not load history.")
		return
	}
	m.rt.Server().Render(w, r, http.StatusOK, "deploy/history.html", "Deployment history",
		map[string]any{"Deployments": list, "CanViewJobs": m.can(r, rbac.JobsView)})
}

// --- audit helpers ---

func (m *module) event(r *http.Request, action, target string) audit.Event {
	ev := audit.Event{Action: action, Target: target, Outcome: audit.OutcomeSuccess, UserAgent: r.UserAgent(),
		RequestID: web.RequestIDFrom(r.Context())}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ev.SourceIP = host
	} else {
		ev.SourceIP = r.RemoteAddr
	}
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		ev.ActorID, ev.Actor = p.ID, p.Username
	}
	return ev
}

func (m *module) record(ctx context.Context, ev audit.Event) {
	if err := m.audit.Record(ctx, ev); err != nil {
		m.log.Warn("audit record failed", "action", ev.Action, "err", err)
	}
}
