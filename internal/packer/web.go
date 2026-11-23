package packer

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

//go:embed templates/*.html
var templatesFS embed.FS

type module struct {
	svc      *Service
	srv      *web.Server
	clusters func() []string // configured cluster names (fallback without Inventory)
}

// NewModule returns the /build web module.
func NewModule(svc *Service, srv *web.Server, clusters func() []string) web.Module {
	return &module{svc: svc, srv: srv, clusters: clusters}
}

func (m *module) Name() string { return "packer" }

func (m *module) Templates() fs.FS {
	sub, _ := fs.Sub(templatesFS, "templates")
	return sub
}

func (m *module) Nav() []web.NavItem {
	return []web.NavItem{{Label: "Build", Path: "/build", Permission: rbac.ImagesView}}
}

func (m *module) Routes(rt *web.Router) {
	rt.HandleFunc("GET /build", rbac.ImagesView, m.index)
	rt.HandleFunc("POST /build", rbac.ImagesBuild, m.submit)
	rt.HandleFunc("GET /build/{id}", rbac.ImagesView, m.detail)
}

type appChoice struct {
	ID, Name, Category string
	Checked, Default   bool
}

type bundleChoice struct {
	ID, Name string
	Apps     []string
	Checked  bool
}

type wizardData struct {
	CanBuild  bool
	Images    []*catalog.Image
	Image     *catalog.Image
	Clusters  []string
	Nodes     []string
	Storages  []string
	Apps      []appChoice
	Bundles   []bundleChoice
	Req       BuildRequest
	Errors    FieldErrors
	Builds    []*Build
	Problem   string
	HasCreds  bool
	ImageIsOK bool
}

func (m *module) canBuild(r *http.Request) bool {
	return m.srv.Authorizer().Authorize(r.Context(), auth.PrincipalFrom(r.Context()), rbac.ImagesBuild) == nil
}

func (m *module) inventory() Inventory {
	inv, _ := m.svc.creds().(Inventory)
	return inv
}

// wizard fills the form choices for req.
func (m *module) wizard(ctx context.Context, req BuildRequest) wizardData {
	c := m.svc.cat.Catalog()
	d := wizardData{Images: c.ImageList(), Req: req, HasCreds: m.svc.creds() != nil}
	if img, ok := c.Images[req.ImageID]; ok {
		d.Image = img
	} else if len(d.Images) > 0 {
		d.Image = d.Images[0]
		d.Req.ImageID = d.Image.ID
	}
	inv := m.inventory()
	if inv != nil {
		ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		d.Clusters, _ = inv.Clusters(ictx)
		if d.Req.Cluster == "" && len(d.Clusters) > 0 {
			d.Req.Cluster = d.Clusters[0]
		}
		if d.Req.Cluster != "" {
			d.Nodes, _ = inv.Nodes(ictx, d.Req.Cluster)
			if d.Req.Node != "" {
				d.Storages, _ = inv.Storages(ictx, d.Req.Cluster, d.Req.Node)
			}
		}
	} else if m.clusters != nil {
		d.Clusters = m.clusters()
	}
	if d.Image == nil {
		return d
	}
	img := d.Image
	if d.Req.TemplateName == "" {
		d.Req.TemplateName = DefaultTemplateName(img.ID, time.Now())
	}
	for _, a := range c.AppList() {
		if !a.Supports(img.OSFamily, img.DistroFamily) {
			continue
		}
		d.Apps = append(d.Apps, appChoice{
			ID: a.ID, Name: a.Name, Category: a.Category,
			Checked: slices.Contains(d.Req.Apps, a.ID),
			Default: slices.Contains(img.DefaultApps, a.ID),
		})
	}
	for _, b := range c.BundleList() {
		var avail []string
		for _, id := range b.Apps {
			if a, ok := c.Apps[id]; ok && a.Supports(img.OSFamily, img.DistroFamily) {
				avail = append(avail, id)
			}
		}
		if len(avail) == 0 {
			continue
		}
		d.Bundles = append(d.Bundles, bundleChoice{ID: b.ID, Name: b.Name, Apps: avail, Checked: slices.Contains(d.Req.Bundles, b.ID)})
	}
	return d
}

// DefaultTemplateName is "<image>-<yyyymmdd>" with dots replaced.
func DefaultTemplateName(imageID string, t time.Time) string {
	return strings.ReplaceAll(imageID, ".", "-") + "-" + t.UTC().Format("20060102")
}

func (m *module) index(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := BuildRequest{ImageID: q.Get("image"), Cluster: q.Get("cluster"), Node: q.Get("node")}
	d := m.wizard(r.Context(), req)
	d.CanBuild = m.canBuild(r)
	builds, err := m.svc.Builds(r.Context(), 50)
	if err != nil {
		m.srv.Logger().Error("list builds", "err", err)
	}
	d.Builds = builds
	m.srv.Render(w, r, http.StatusOK, "packer/build.html", "Build", d)
}

func parseRequest(r *http.Request) BuildRequest {
	f := r.PostForm
	atoi := func(k string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(f.Get(k)))
		return n
	}
	trim := func(k string) string { return strings.TrimSpace(f.Get(k)) }
	return BuildRequest{
		ImageID: trim("image"), Cluster: trim("cluster"), Node: trim("node"),
		Storage: trim("storage"), ISOStorage: trim("iso_storage"), Bridge: trim("bridge"),
		Cores: atoi("cores"), Memory: atoi("memory"), Disk: strings.ToUpper(trim("disk")),
		ISOFile: trim("iso_file"), VirtioISOFile: trim("virtio_iso_file"),
		Apps: f["apps"], Bundles: f["bundles"], SkipDefaultApps: f.Get("skip_default_apps") != "",
		TemplateName: trim("template_name"), VMID: atoi("vm_id"),
	}
}

func (m *module) submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		m.srv.Error(w, r, http.StatusBadRequest, "Invalid form.")
		return
	}
	req := parseRequest(r)
	p := auth.PrincipalFrom(r.Context())
	actor, actorID := "", ""
	if p != nil {
		actor, actorID = p.Username, p.ID
	}
	ev := audit.Event{
		Actor: actor, ActorID: actorID, Action: "image.build.start", Outcome: audit.OutcomeSuccess,
		SourceIP: remoteIP(r), UserAgent: r.UserAgent(), RequestID: web.RequestIDFrom(r.Context()),
		Details: map[string]any{"image": req.ImageID, "cluster": req.Cluster, "node": req.Node,
			"template_name": req.TemplateName, "vm_id": req.VMID, "apps": req.Apps, "bundles": req.Bundles},
	}
	b, err := m.svc.Submit(r.Context(), req, actor)
	if err != nil {
		var fe FieldErrors
		ev.Outcome = audit.OutcomeFailure
		if errors.As(err, &fe) {
			ev.Reason = "invalid request"
			_ = m.svc.audit.Record(r.Context(), ev)
			d := m.wizard(r.Context(), req)
			d.CanBuild = true
			d.Errors = fe
			d.Builds, _ = m.svc.Builds(r.Context(), 50)
			m.srv.Render(w, r, http.StatusUnprocessableEntity, "packer/build.html", "Build", d)
			return
		}
		ev.Reason = "internal error"
		_ = m.svc.audit.Record(r.Context(), ev)
		m.srv.Logger().Error("submit build", "err", err)
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not start the build.")
		return
	}
	ev.Target = "build:" + b.ID
	ev.Details["job_id"] = b.JobID
	ev.Details["resolved_apps"] = b.Apps
	_ = m.svc.audit.Record(r.Context(), ev)
	http.Redirect(w, r, "/jobs/"+b.JobID, http.StatusSeeOther)
}

func (m *module) detail(w http.ResponseWriter, r *http.Request) {
	b, err := m.svc.Build(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrBuildNotFound) {
		m.srv.Error(w, r, http.StatusNotFound, "Build not found.")
		return
	}
	if err != nil {
		m.srv.Logger().Error("get build", "err", err)
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not load the build.")
		return
	}
	m.srv.Render(w, r, http.StatusOK, "packer/detail.html", "Build "+b.TemplateName, b)
}

func remoteIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
