package catalog

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"slices"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// module serves /catalog.
type module struct {
	store *Store
	srv   *web.Server
	audit audit.Recorder
}

// NewModule returns the catalog web module.
func NewModule(store *Store, srv *web.Server, rec audit.Recorder) web.Module {
	if rec == nil {
		rec = audit.NopRecorder{}
	}
	return &module{store: store, srv: srv, audit: rec}
}

func (m *module) Name() string { return "catalog" }

func (m *module) Templates() fs.FS {
	sub, _ := fs.Sub(templatesFS, "templates")
	return sub
}

func (m *module) Nav() []web.NavItem {
	return []web.NavItem{{Label: "Catalog", Path: "/catalog", Permission: rbac.CatalogView}}
}

func (m *module) Routes(rt *web.Router) {
	static, _ := fs.Sub(staticFS, "static")
	rt.HandlePublic("GET /catalog/static/", http.StripPrefix("/catalog/static/", http.FileServerFS(static)))
	rt.HandleFunc("GET /catalog", rbac.CatalogView, m.index)
	rt.HandleFunc("GET /catalog/images/{id}", rbac.CatalogView, m.image)
	rt.HandleFunc("GET /catalog/apps/{id}", rbac.CatalogView, m.app)
	rt.HandleFunc("GET /catalog/bundles/{id}", rbac.CatalogView, m.bundle)

	rt.HandleFunc("GET /catalog/apps/new", rbac.CatalogManage, m.editor(KindApp, ModeCreate))
	rt.HandleFunc("GET /catalog/apps/{id}/edit", rbac.CatalogManage, m.editor(KindApp, ModeEdit))
	rt.HandleFunc("GET /catalog/apps/{id}/clone", rbac.CatalogManage, m.editor(KindApp, ModeClone))
	rt.HandleFunc("GET /catalog/bundles/new", rbac.CatalogManage, m.editor(KindBundle, ModeCreate))
	rt.HandleFunc("GET /catalog/bundles/{id}/edit", rbac.CatalogManage, m.editor(KindBundle, ModeEdit))
	rt.HandleFunc("GET /catalog/bundles/{id}/clone", rbac.CatalogManage, m.editor(KindBundle, ModeClone))
	rt.HandleFunc("POST /catalog/apps", rbac.CatalogManage, m.save(KindApp))
	rt.HandleFunc("POST /catalog/bundles", rbac.CatalogManage, m.save(KindBundle))
	rt.HandleFunc("POST /catalog/apps/{id}/revert", rbac.CatalogManage, m.revert(KindApp))
	rt.HandleFunc("POST /catalog/bundles/{id}/revert", rbac.CatalogManage, m.revert(KindBundle))
	rt.HandleFunc("POST /catalog/reload", rbac.CatalogManage, m.reload)
}

type indexData struct {
	Q, Tab, OS, Category string
	Categories           []string
	Images               []*Image
	Apps                 []*App
	Bundles              []*Bundle
	Problems             []Problem
	CanManage            bool
	WriteDir             string
	Total                [3]int
}

func (m *module) canManage(r *http.Request) bool {
	return m.srv.Authorizer().Authorize(r.Context(), auth.PrincipalFrom(r.Context()), rbac.CatalogManage) == nil
}

func (m *module) index(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := indexData{
		Q:          strings.TrimSpace(q.Get("q")),
		Tab:        q.Get("tab"),
		OS:         q.Get("os"),
		Category:   q.Get("category"),
		Categories: Categories,
		CanManage:  m.canManage(r),
		WriteDir:   m.store.WriteDir(),
	}
	switch d.Tab {
	case "images", "apps", "bundles":
	default:
		d.Tab = "apps"
	}
	if d.OS != "windows" && d.OS != "linux" {
		d.OS = ""
	}
	if !slices.Contains(Categories, d.Category) {
		d.Category = ""
	}
	c := m.store.Catalog()
	d.Total = [3]int{len(c.Images), len(c.Apps), len(c.Bundles)}
	terms := strings.Fields(strings.ToLower(d.Q))
	for _, img := range c.ImageList() {
		if (d.OS == "" || string(img.OSFamily) == d.OS) &&
			matches(terms, img.ID, img.Name, img.Description, img.OS, img.Version, strings.Join(img.Tags, " ")) {
			d.Images = append(d.Images, img)
		}
	}
	for _, a := range c.AppList() {
		if (d.OS == "" || slices.Contains(a.OSFamilies(), OSFamily(d.OS))) &&
			(d.Category == "" || a.Category == d.Category) &&
			matches(terms, a.ID, a.Name, a.Description, a.Category) {
			d.Apps = append(d.Apps, a)
		}
	}
	for _, b := range c.BundleList() {
		if matches(terms, b.ID, b.Name, b.Description, strings.Join(b.Apps, " ")) {
			d.Bundles = append(d.Bundles, b)
		}
	}
	if d.CanManage {
		d.Problems = c.Problems
	}
	if r.Header.Get("HX-Request") != "" && r.Header.Get("HX-Target") == "catalog-results" {
		m.srv.RenderPartial(w, r, "catalog/index.html", "results", d)
		return
	}
	m.srv.Render(w, r, http.StatusOK, "catalog/index.html", "Catalog", d)
}

func matches(terms []string, fields ...string) bool {
	if len(terms) == 0 {
		return true
	}
	hay := strings.ToLower(strings.Join(fields, " "))
	for _, t := range terms {
		if !strings.Contains(hay, t) {
			return false
		}
	}
	return true
}

type itemData struct {
	Image      *Image
	App        *App
	Bundle     *Bundle
	BundleApps []*App
	UsedBy     []*Bundle
	Raw        string
	CanManage  bool
	IsOverride bool
	Embedded   bool
}

func (m *module) image(w http.ResponseWriter, r *http.Request) {
	c := m.store.Catalog()
	img, ok := c.Images[r.PathValue("id")]
	if !ok {
		m.srv.Error(w, r, http.StatusNotFound, "Image not found.")
		return
	}
	raw, _ := m.store.Raw("image", img.ID)
	m.srv.Render(w, r, http.StatusOK, "catalog/image.html", img.Name,
		itemData{Image: img, Raw: string(raw), CanManage: m.canManage(r)})
}

func (m *module) app(w http.ResponseWriter, r *http.Request) {
	c := m.store.Catalog()
	a, ok := c.Apps[r.PathValue("id")]
	if !ok {
		m.srv.Error(w, r, http.StatusNotFound, "App not found.")
		return
	}
	d := itemData{App: a, CanManage: m.canManage(r), IsOverride: m.store.IsOverride(a.Source), Embedded: a.Source.Embedded()}
	for _, b := range c.BundleList() {
		if slices.Contains(b.Apps, a.ID) {
			d.UsedBy = append(d.UsedBy, b)
		}
	}
	raw, _ := m.store.Raw(KindApp, a.ID)
	d.Raw = string(raw)
	m.srv.Render(w, r, http.StatusOK, "catalog/app.html", a.Name, d)
}

func (m *module) bundle(w http.ResponseWriter, r *http.Request) {
	c := m.store.Catalog()
	b, ok := c.Bundles[r.PathValue("id")]
	if !ok {
		m.srv.Error(w, r, http.StatusNotFound, "Bundle not found.")
		return
	}
	d := itemData{Bundle: b, CanManage: m.canManage(r), IsOverride: m.store.IsOverride(b.Source), Embedded: b.Source.Embedded()}
	for _, id := range b.Apps {
		if a, ok := c.Apps[id]; ok {
			d.BundleApps = append(d.BundleApps, a)
		}
	}
	raw, _ := m.store.Raw(KindBundle, b.ID)
	d.Raw = string(raw)
	m.srv.Render(w, r, http.StatusOK, "catalog/bundle.html", b.Name, d)
}

type editData struct {
	Kind       Kind
	Mode       string
	OriginalID string
	YAML       string
	Problems   []Problem
	WriteDir   string
	Action     string
	// Validated is set after an explicit "Validate" with no problems.
	Validated bool
}

const appSkeleton = `id: my-app
name: My App
category: utility
description: One-line description.
homepage: https://example.com
depends_on: []
reboot_required: false
install:
  windows:
    - winget:
        id: Vendor.MyApp
      verify: 'if (Test-Path "$env:ProgramFiles\MyApp\myapp.exe") { exit 0 } else { exit 1 }'
  linux:
    - apt:
        packages: [my-app]
      verify: command -v my-app
    - dnf:
        packages: [my-app]
      verify: command -v my-app
`

const bundleSkeleton = `id: my-bundle
name: My bundle
description: Apps that belong together.
apps: [git, curl]
`

func (m *module) editor(kind Kind, mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := editData{Kind: kind, Mode: mode, WriteDir: m.store.WriteDir(), Action: "/catalog/" + kind.dir()}
		switch mode {
		case ModeCreate:
			d.YAML = appSkeleton
			if kind == KindBundle {
				d.YAML = bundleSkeleton
			}
		default:
			id := r.PathValue("id")
			raw, err := m.store.Raw(kind, id)
			if err != nil {
				m.srv.Error(w, r, http.StatusNotFound, "Item not found.")
				return
			}
			d.YAML = string(raw)
			if mode == ModeEdit {
				d.OriginalID = id
			} else {
				d.YAML = renameID(d.YAML, id, id+"-copy")
			}
		}
		m.srv.Render(w, r, http.StatusOK, "catalog/edit.html", editTitle(kind, mode), d)
	}
}

func editTitle(kind Kind, mode string) string {
	name := "app"
	if kind == KindBundle {
		name = "bundle"
	}
	switch mode {
	case ModeEdit:
		return "Edit " + name
	case ModeClone:
		return "Clone " + name
	}
	return "New " + name
}

// renameID rewrites the top-level "id:" line of a definition.
func renameID(yamlText, from, to string) string {
	lines := strings.Split(yamlText, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "id:") && strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "id:")), `"'`) == from {
			lines[i] = "id: " + to
			break
		}
	}
	return strings.Join(lines, "\n")
}

func (m *module) event(r *http.Request, action, target string, outcome audit.Outcome, reason string, details map[string]any) audit.Event {
	p := auth.PrincipalFrom(r.Context())
	ev := audit.Event{
		Action: action, Target: target, Outcome: outcome, Reason: reason,
		SourceIP: clientIP(r), UserAgent: r.UserAgent(), RequestID: web.RequestIDFrom(r.Context()), Details: details,
	}
	if p != nil {
		ev.ActorID, ev.Actor = p.ID, p.Username
	}
	return ev
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

func (m *module) save(kind Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxDefinitionBytes+16<<10)
		if err := r.ParseForm(); err != nil {
			m.srv.Error(w, r, http.StatusBadRequest, "Invalid form.")
			return
		}
		mode := r.PostForm.Get("mode")
		orig := r.PostForm.Get("original_id")
		text := strings.ReplaceAll(r.PostForm.Get("yaml"), "\r\n", "\n")
		d := editData{Kind: kind, Mode: mode, OriginalID: orig, YAML: text, WriteDir: m.store.WriteDir(),
			Action: "/catalog/" + kind.dir()}

		if r.PostForm.Get("action") == "validate" {
			d.Problems = m.store.Check(kind, []byte(text), mode, orig).Problems
			d.Validated = len(d.Problems) == 0
			if r.Header.Get("HX-Request") != "" {
				m.srv.RenderPartial(w, r, "catalog/edit.html", "problems", d)
				return
			}
			m.srv.Render(w, r, http.StatusOK, "catalog/edit.html", editTitle(kind, mode), d)
			return
		}

		res, err := m.store.Save(r.Context(), kind, []byte(text), mode, orig)
		action := "catalog." + string(kind) + "." + map[string]string{ModeCreate: "create", ModeEdit: "update", ModeClone: "clone"}[mode]
		if action == "catalog."+string(kind)+"." {
			action += "save"
		}
		target := string(kind) + ":" + res.ID
		details := map[string]any{"path": res.Path, "mode": mode}
		if orig != "" {
			details["original_id"] = orig
		}
		switch {
		case errors.Is(err, ErrInvalid):
			details["problems"] = len(res.Problems)
			_ = m.audit.Record(r.Context(), m.event(r, action, target, audit.OutcomeFailure, "validation failed", details))
			d.Problems = res.Problems
			m.srv.Render(w, r, http.StatusUnprocessableEntity, "catalog/edit.html", editTitle(kind, mode), d)
			return
		case errors.Is(err, ErrNoWriteDir):
			m.srv.Error(w, r, http.StatusConflict, "No catalog override directory is configured (catalog.dirs).")
			return
		case err != nil:
			m.srv.Logger().Error("catalog save", "kind", kind, "id", res.ID, "err", err)
			_ = m.audit.Record(r.Context(), m.event(r, action, target, audit.OutcomeFailure, "internal error", details))
			m.srv.Error(w, r, http.StatusInternalServerError, "Could not save the definition.")
			return
		}
		details["overrode"] = res.Overrode
		_ = m.audit.Record(r.Context(), m.event(r, action, target, audit.OutcomeSuccess, "", details))
		http.Redirect(w, r, "/catalog/"+kind.dir()+"/"+res.ID, http.StatusSeeOther)
	}
}

func (m *module) revert(kind Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		p, err := m.store.DeleteOverride(r.Context(), kind, id)
		target := string(kind) + ":" + id
		action := "catalog." + string(kind) + ".delete"
		switch {
		case errors.Is(err, ErrNotFound):
			m.srv.Error(w, r, http.StatusNotFound, "No override file for this item.")
			return
		case errors.Is(err, ErrNoWriteDir):
			m.srv.Error(w, r, http.StatusConflict, "No catalog override directory is configured.")
			return
		case err != nil:
			m.srv.Logger().Error("catalog delete override", "kind", kind, "id", id, "err", err)
			_ = m.audit.Record(r.Context(), m.event(r, action, target, audit.OutcomeFailure, "internal error", map[string]any{"path": p}))
			m.srv.Error(w, r, http.StatusInternalServerError, "Could not delete the override.")
			return
		}
		_ = m.audit.Record(r.Context(), m.event(r, action, target, audit.OutcomeSuccess, "", map[string]any{"path": p}))
		c := m.store.Catalog()
		if _, ok := c.Apps[id]; ok && kind == KindApp {
			http.Redirect(w, r, "/catalog/apps/"+id, http.StatusSeeOther)
			return
		}
		if _, ok := c.Bundles[id]; ok && kind == KindBundle {
			http.Redirect(w, r, "/catalog/bundles/"+id, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/catalog?tab="+kind.dir(), http.StatusSeeOther)
	}
}

func (m *module) reload(w http.ResponseWriter, r *http.Request) {
	_, err := m.store.Reload(r.Context(), true)
	outcome, reason := audit.OutcomeSuccess, ""
	if err != nil {
		m.srv.Logger().Error("catalog reload", "err", err)
		outcome, reason = audit.OutcomeFailure, "reload failed"
	}
	_ = m.audit.Record(r.Context(), m.event(r, "catalog.reload", "catalog", outcome, reason, nil))
	if err != nil {
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not reload the catalog.")
		return
	}
	http.Redirect(w, r, "/catalog", http.StatusSeeOther)
}
