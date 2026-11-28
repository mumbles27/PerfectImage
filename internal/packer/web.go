package packer

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
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
	// htmx: re-render the wizard after the image, cluster, node or ISO
	// storage changed, keeping everything already entered.
	rt.HandleFunc("POST /build/form", rbac.ImagesBuild, m.refresh)
	rt.HandleFunc("GET /build/{id}", rbac.ImagesView, m.detail)
}

// maxFormBytes bounds the wizard form (the post-install script dominates).
const maxFormBytes = MaxPostScriptBytes + 64<<10

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
	CanBuild    bool
	Images      []*catalog.Image
	Image       *catalog.Image
	Clusters    []string
	Nodes       []string
	Storages    []string
	Bridges     []string
	ISOStorages []string
	ISOs        []string
	Apps        []appChoice
	Bundles     []bundleChoice
	Req         BuildRequest
	Errors      FieldErrors
	Builds      []*Build
	Problem     string
	// InventoryError explains why cluster lists could not be loaded.
	InventoryError string
	HasCreds       bool
	ImageIsOK      bool
	// AutoName is the generated template name; when the submitted name still
	// equals it, an image change regenerates it.
	AutoName  string
	Timezones []string
	Locales   []string
	Keyboards []string
}

// IsWindows reports whether the selected image is a Windows image.
func (d wizardData) IsWindows() bool { return d.Image != nil && d.Image.OSFamily == catalog.Windows }

// Suggestions offered by the OS settings fields (any valid value is accepted).
var (
	linuxTimezones = []string{"UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
		"America/Sao_Paulo", "Europe/London", "Europe/Berlin", "Europe/Paris", "Asia/Kolkata", "Asia/Singapore",
		"Asia/Tokyo", "Australia/Sydney"}
	windowsTimezones = []string{"UTC", "Eastern Standard Time", "Central Standard Time", "Mountain Standard Time",
		"Pacific Standard Time", "E. South America Standard Time", "GMT Standard Time", "W. Europe Standard Time",
		"Romance Standard Time", "India Standard Time", "Singapore Standard Time", "Tokyo Standard Time",
		"AUS Eastern Standard Time"}
	locales         = []string{"en-US", "en-GB", "de-DE", "fr-FR", "es-ES", "it-IT", "nl-NL", "pt-BR", "ja-JP"}
	linuxKeyboards  = []string{"us", "gb", "de", "fr", "es", "it", "nl", "br", "jp", "us-intl"}
	windowsKeyboard = []string{"en-US", "en-GB", "de-DE", "fr-FR", "es-ES", "it-IT", "nl-NL", "pt-BR", "ja-JP"}
)

func (m *module) canBuild(r *http.Request) bool {
	return m.srv.Authorizer().Authorize(r.Context(), auth.PrincipalFrom(r.Context()), rbac.ImagesBuild) == nil
}

func (m *module) inventory() Inventory {
	inv, _ := m.svc.creds().(Inventory)
	return inv
}

// wizard fills the form choices for req. autoName is the template name the
// previous render generated (see wizardData.AutoName).
func (m *module) wizard(ctx context.Context, req BuildRequest, autoName string) wizardData {
	c := m.svc.cat.Catalog()
	d := wizardData{Images: c.ImageList(), Req: req, HasCreds: m.svc.creds() != nil, Locales: locales}
	if img, ok := c.Images[req.ImageID]; ok {
		d.Image = img
	} else if len(d.Images) > 0 {
		d.Image = d.Images[0]
		d.Req.ImageID = d.Image.ID
	}
	m.fillTargets(ctx, &d)
	if d.Image == nil {
		return d
	}
	img := d.Image
	d.AutoName = DefaultTemplateName(img.ID, time.Now())
	if d.Req.TemplateName == "" || (autoName != "" && d.Req.TemplateName == autoName) {
		d.Req.TemplateName = d.AutoName
	}
	if d.IsWindows() {
		d.Timezones, d.Keyboards = windowsTimezones, windowsKeyboard
	} else {
		d.Timezones, d.Keyboards = linuxTimezones, linuxKeyboards
	}
	if !slices.Contains(img.Editions, d.Req.Settings.WindowsEdition) {
		d.Req.Settings.WindowsEdition = ""
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

// fillTargets loads clusters, nodes, storages, bridges and ISOs from the
// credential provider's inventory. The selected cluster and node default to
// the first entries (or the cluster's saved default node); disk storage and
// bridge default to the cluster's saved defaults when the image's own
// defaults do not exist on the node.
func (m *module) fillTargets(ctx context.Context, d *wizardData) {
	inv := m.inventory()
	if inv == nil {
		if m.clusters != nil {
			d.Clusters = m.clusters()
		}
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var err error
	if d.Clusters, err = inv.Clusters(ctx); err != nil {
		d.InventoryError = "Could not list clusters: " + err.Error()
		return
	}
	if len(d.Clusters) == 0 {
		return
	}
	if !slices.Contains(d.Clusters, d.Req.Cluster) {
		d.Req.Cluster = d.Clusters[0]
	}
	media, _ := m.svc.creds().(MediaInventory)
	var defs TargetDefaults
	if media != nil {
		defs, _ = media.Defaults(ctx, d.Req.Cluster)
	}
	if d.Nodes, err = inv.Nodes(ctx, d.Req.Cluster); err != nil {
		d.InventoryError = fmt.Sprintf("Could not reach cluster %s: %v", d.Req.Cluster, err)
		return
	}
	if len(d.Nodes) == 0 {
		return
	}
	if !slices.Contains(d.Nodes, d.Req.Node) {
		d.Req.Node = d.Nodes[0]
		if slices.Contains(d.Nodes, defs.Node) {
			d.Req.Node = defs.Node
		}
	}
	if d.Storages, err = inv.Storages(ctx, d.Req.Cluster, d.Req.Node); err != nil {
		d.InventoryError = fmt.Sprintf("Could not list storages on %s: %v", d.Req.Node, err)
	}
	if media == nil {
		return
	}
	if d.Bridges, err = media.Bridges(ctx, d.Req.Cluster, d.Req.Node); err != nil {
		d.InventoryError = fmt.Sprintf("Could not list bridges on %s: %v", d.Req.Node, err)
	}
	if d.ISOStorages, err = media.ISOStorages(ctx, d.Req.Cluster, d.Req.Node); err != nil {
		d.InventoryError = fmt.Sprintf("Could not list ISO storages on %s: %v", d.Req.Node, err)
	}
	for _, st := range d.ISOStorages {
		isos, err := media.ISOs(ctx, d.Req.Cluster, d.Req.Node, st)
		if err != nil {
			d.InventoryError = fmt.Sprintf("Could not list ISOs on %s: %v", st, err)
			continue
		}
		d.ISOs = append(d.ISOs, isos...)
	}
	if img := d.Image; img != nil {
		if d.Req.Storage == "" && !slices.Contains(d.Storages, img.Resources.Storage) && slices.Contains(d.Storages, defs.Storage) {
			d.Req.Storage = defs.Storage
		}
		if d.Req.Bridge == "" && !slices.Contains(d.Bridges, img.Resources.Bridge) && slices.Contains(d.Bridges, defs.Bridge) {
			d.Req.Bridge = defs.Bridge
		}
	}
	if d.Req.ISOStorage == "" && len(d.ISOStorages) > 0 && !slices.Contains(d.ISOStorages, "local") {
		d.Req.ISOStorage = d.ISOStorages[0]
	}
	// Keep values that are not (or no longer) listed selectable.
	d.Storages = ensure(d.Storages, d.Req.Storage)
	d.Bridges = ensure(d.Bridges, d.Req.Bridge)
	d.ISOStorages = ensure(d.ISOStorages, d.Req.ISOStorage)
	d.ISOs = ensure(ensure(d.ISOs, d.Req.ISOFile), d.Req.VirtioISOFile)
}

func ensure(list []string, v string) []string {
	if v == "" || slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// HasMedia reports whether ISO and bridge lists come from the cluster (the
// form then offers selects instead of free text).
func (d wizardData) HasMedia() bool { return len(d.ISOStorages) > 0 }

// DefaultTemplateName is "<image>-<yyyymmdd>" with dots replaced.
func DefaultTemplateName(imageID string, t time.Time) string {
	return strings.ReplaceAll(imageID, ".", "-") + "-" + t.UTC().Format("20060102")
}

func (m *module) index(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := BuildRequest{ImageID: q.Get("image"), Cluster: q.Get("cluster"), Node: q.Get("node")}
	d := m.wizard(r.Context(), req, "")
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
		Settings: OSSettings{
			Timezone: trim("timezone"), Locale: trim("locale"), Keyboard: trim("keyboard"),
			Updates: f.Get("os_updates") != "", WindowsEdition: trim("windows_edition"),
		},
		PostScript: PostScript{Script: f.Get("post_script"), Reboot: f.Get("post_script_reboot") != ""},
	}
}

// refresh re-renders the wizard from the submitted (partial) form.
func (m *module) refresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		m.srv.Error(w, r, http.StatusBadRequest, "Invalid form.")
		return
	}
	d := m.wizard(r.Context(), parseRequest(r), r.PostFormValue("auto_name"))
	d.CanBuild = true
	m.srv.Render(w, r, http.StatusOK, "packer/build.html", "Build", d)
}

func (m *module) submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
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
			"template_name": req.TemplateName, "vm_id": req.VMID, "apps": req.Apps, "bundles": req.Bundles,
			"settings": req.Settings},
	}
	if ps := req.PostScript.Script; ps != "" {
		// The script itself stays in the build record; the audit trail gets
		// a fingerprint so a later change to the record is detectable.
		sum := sha256.Sum256([]byte(ps))
		ev.Details["post_script_sha256"] = hex.EncodeToString(sum[:])
		ev.Details["post_script_bytes"] = len(ps)
	}
	b, err := m.svc.Submit(r.Context(), req, actor)
	if err != nil {
		var fe FieldErrors
		ev.Outcome = audit.OutcomeFailure
		if errors.As(err, &fe) {
			ev.Reason = "invalid request"
			_ = m.svc.audit.Record(r.Context(), ev)
			d := m.wizard(r.Context(), req, r.PostFormValue("auto_name"))
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
