package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

//go:embed templates
var templatesFS embed.FS

// PageData is the value passed to every page template.
type PageData struct {
	Title     string
	Nav       []NavLink
	Principal *auth.Principal
	CSRFToken string
	RequestID string
	Version   string
	// Data is the page-specific payload.
	Data any
}

// NavLink is a NavItem resolved for the current request.
type NavLink struct {
	NavItem
	Active bool
}

type renderer struct {
	pages map[string]*template.Template
}

// Funcs are the template helpers available to every template.
var Funcs = template.FuncMap{
	"fmtTime": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			if v.IsZero() {
				return "—"
			}
			return v.Local().Format("2006-01-02 15:04:05")
		case *time.Time:
			if v == nil || v.IsZero() {
				return "—"
			}
			return v.Local().Format("2006-01-02 15:04:05")
		}
		return "—"
	},
	"statusClass": func(s jobs.Status) string { return "status status-" + string(s) },
	"hasPerm": func(p *auth.Principal, perm string) bool {
		return p.Has(rbac.Permission(perm))
	},
	"shortID": func(id string) string {
		if len(id) > 12 {
			return id[:12]
		}
		return id
	},
}

func newRenderer(s *Server, modules []Module) (*renderer, error) {
	base, err := template.New("base").Funcs(Funcs).ParseFS(templatesFS, "templates/layout.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse layout: %w", err)
	}
	r := &renderer{pages: map[string]*template.Template{}}
	add := func(ns string, fsys fs.FS) error {
		files, err := fs.Glob(fsys, "*.html")
		if err != nil {
			return err
		}
		for _, f := range files {
			t, err := base.Clone()
			if err != nil {
				return err
			}
			if _, err := t.ParseFS(fsys, f); err != nil {
				return fmt.Errorf("web: parse %s/%s: %w", ns, f, err)
			}
			r.pages[ns+"/"+path.Base(f)] = t
		}
		return nil
	}
	coreFS, err := fs.Sub(templatesFS, "templates/pages")
	if err != nil {
		return nil, err
	}
	if err := add("core", coreFS); err != nil {
		return nil, err
	}
	for _, m := range modules {
		if tp, ok := m.(TemplateProvider); ok && m.Name() != "core" {
			if err := add(m.Name(), tp.Templates()); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

func mergeNav(core []NavItem, extra ...[]NavItem) []NavItem {
	byPath := map[string]NavItem{}
	for _, n := range core {
		byPath[n.Path] = n
	}
	for _, list := range extra {
		for _, n := range list {
			if old, ok := byPath[n.Path]; ok && n.Order == 0 {
				n.Order = old.Order
			}
			byPath[n.Path] = n
		}
	}
	out := make([]NavItem, 0, len(byPath))
	for _, n := range byPath {
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func (s *Server) pageData(r *http.Request, title string, data any) PageData {
	p := auth.PrincipalFrom(r.Context())
	pd := PageData{
		Title:     title,
		Principal: p,
		CSRFToken: s.CSRFToken(r),
		RequestID: RequestIDFrom(r.Context()),
		Version:   s.opts.Version,
		Data:      data,
	}
	if p == nil {
		return pd
	}
	authz := s.authorizer()
	for _, n := range s.nav {
		if n.Permission != "" && authz.Authorize(r.Context(), p, n.Permission) != nil {
			continue
		}
		active := r.URL.Path == n.Path || (n.Path != "/" && strings.HasPrefix(r.URL.Path, n.Path+"/"))
		pd.Nav = append(pd.Nav, NavLink{NavItem: n, Active: active})
	}
	return pd
}

// Render executes page template name ("<module>/<file>.html") inside the base
// layout. Output is buffered so template errors produce a clean 500.
func (s *Server) Render(w http.ResponseWriter, r *http.Request, status int, name, title string, data any) {
	s.execute(w, r, status, name, "layout", s.pageData(r, title, data))
}

// RenderPartial executes a single named block (e.g. a table fragment for
// htmx) from page template name, with the same PageData as Render.
func (s *Server) RenderPartial(w http.ResponseWriter, r *http.Request, name, block string, data any) {
	s.execute(w, r, http.StatusOK, name, block, s.pageData(r, "", data))
}

func (s *Server) execute(w http.ResponseWriter, r *http.Request, status int, name, block string, pd PageData) {
	t, ok := s.renderer.pages[name]
	if !ok {
		s.log.Error("unknown template", "template", name)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, block, pd); err != nil {
		s.log.Error("render template", "template", name, "block", block, "err", err,
			"request_id", RequestIDFrom(r.Context()))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

type errorData struct {
	Status  int
	Text    string
	Message string
}

// Error renders the error page (or plain text for htmx/SSE requests).
func (s *Server) Error(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if r.Header.Get("HX-Request") != "" || strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
		s.renderer == nil {
		http.Error(w, msg, status)
		return
	}
	s.Render(w, r, status, "core/error.html", http.StatusText(status),
		errorData{Status: status, Text: http.StatusText(status), Message: msg})
}

func (s *Server) placeholder(item NavItem) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.Render(w, r, http.StatusOK, "core/placeholder.html", item.Label, item)
	}
}
