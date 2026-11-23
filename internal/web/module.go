package web

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// Module is a self-contained group of pages/endpoints contributed by a domain
// package. Domain agents implement Module in their own package and add it via
// Server.AddModule (normally from an app.Plugin Init), never by editing the
// core router.
//
//	type buildModule struct{ ... }
//	func (m *buildModule) Name() string { return "packer" }
//	func (m *buildModule) Routes(rt *web.Router) {
//		rt.HandleFunc("GET /build", rbac.ImagesView, m.index)
//		rt.HandleFunc("POST /build", rbac.ImagesBuild, m.start)
//	}
//	func (m *buildModule) Nav() []web.NavItem {
//		return []web.NavItem{{Label: "Build", Path: "/build", Permission: rbac.ImagesView}}
//	}
//	func (m *buildModule) Templates() fs.FS { return templatesFS } // optional
type Module interface {
	// Name is a short unique identifier; it also namespaces templates
	// ("<name>/<file>.html").
	Name() string
	// Routes registers handlers on the router.
	Routes(rt *Router)
	// Nav returns navigation entries. An entry whose Path equals one of the
	// core sections (/build, /deploy, /catalog, /jobs, /audit, /settings)
	// replaces that section's placeholder.
	Nav() []NavItem
}

// TemplateProvider is optionally implemented by a Module to contribute page
// templates. Every *.html file at the root of the FS is parsed together with
// the base layout and is addressable as "<module name>/<file name>". Page
// templates define {{define "content"}} (and optionally "head"/"scripts").
type TemplateProvider interface {
	Templates() fs.FS
}

// NavItem is a top-level navigation entry.
type NavItem struct {
	Label string
	Path  string
	// Permission required to see the entry; empty means any signed-in user.
	Permission rbac.Permission
	// Order sorts entries (lower first). Core sections use 10..70.
	Order int
}

// coreNav defines the canonical sections. Paths without a registered page
// get a "coming soon" placeholder so the navigation is stable while domain
// modules are being built.
var coreNav = []NavItem{
	{Label: "Dashboard", Path: "/", Order: 10},
	{Label: "Build", Path: "/build", Permission: rbac.ImagesView, Order: 20},
	{Label: "Deploy", Path: "/deploy", Permission: rbac.DeployView, Order: 30},
	{Label: "Catalog", Path: "/catalog", Permission: rbac.CatalogView, Order: 40},
	{Label: "Jobs", Path: "/jobs", Permission: rbac.JobsView, Order: 50},
	{Label: "Audit", Path: "/audit", Permission: rbac.AuditView, Order: 60},
	{Label: "Settings", Path: "/settings", Permission: rbac.SettingsView, Order: 70},
}

// Router is handed to Module.Routes. It wraps http.ServeMux (Go 1.22+
// patterns such as "GET /jobs/{id}") and applies authentication and
// authorization per route.
type Router struct {
	s     *Server
	mux   *http.ServeMux
	paths map[string]bool
}

func newRouter(s *Server) *Router {
	return &Router{s: s, mux: http.NewServeMux(), paths: map[string]bool{}}
}

// Handle registers h for pattern, requiring a signed-in principal holding
// perm (empty perm: any signed-in principal).
func (rt *Router) Handle(pattern string, perm rbac.Permission, h http.Handler) {
	rt.HandlePublic(pattern, rt.s.RequirePermission(perm)(h))
}

// HandleFunc is Handle for functions.
func (rt *Router) HandleFunc(pattern string, perm rbac.Permission, h http.HandlerFunc) {
	rt.Handle(pattern, perm, h)
}

// HandlePublic registers h without any authentication requirement (login
// pages, health checks, static assets). CSRF protection still applies.
func (rt *Router) HandlePublic(pattern string, h http.Handler) {
	rt.mux.Handle(pattern, h)
	rt.paths[patternPath(pattern)] = true
}

// Registered reports whether any pattern for path has been registered.
func (rt *Router) Registered(path string) bool { return rt.paths[path] }

// Server returns the owning server (for rendering, auth lookups, etc.).
func (rt *Router) Server() *Server { return rt.s }

// Render renders a full page template ("<module>/<file>.html") with status 200.
func (rt *Router) Render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	rt.s.Render(w, r, http.StatusOK, name, title, data)
}

// patternPath extracts the path portion of a ServeMux pattern
// ("GET host/x/{id}" -> "/x/{id}").
func patternPath(p string) string {
	if _, rest, ok := strings.Cut(p, " "); ok {
		p = strings.TrimSpace(rest)
	}
	if i := strings.Index(p, "/"); i > 0 {
		p = p[i:]
	}
	return strings.TrimSuffix(p, "{$}")
}
