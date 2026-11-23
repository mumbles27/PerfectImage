package web

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// headerAuth authenticates "X-Test-Role: <role>" as a user with that built-in role.
type headerAuth struct{}

func (headerAuth) Authenticate(r *http.Request) (*auth.Principal, error) {
	role := r.Header.Get("X-Test-Role")
	if role == "" {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Principal{ID: role, Username: strings.ToLower(role), Roles: []string{role},
		Permissions: rbac.RolePermissions(role)}, nil
}

type testModule struct{}

func (testModule) Name() string { return "test" }
func (testModule) Routes(rt *Router) {
	rt.HandleFunc("GET /build", rbac.ImagesView, func(w http.ResponseWriter, r *http.Request) {
		rt.Render(w, r, "test/build.html", "Build", "hello-build")
	})
	rt.HandlePublic("GET /login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "login page")
	}))
	rt.HandleFunc("GET /boom", "", func(http.ResponseWriter, *http.Request) { panic("boom") })
}
func (testModule) Nav() []NavItem {
	return []NavItem{
		{Label: "Images", Path: "/build", Permission: rbac.ImagesView},
		{Label: "Extra", Path: "/extra", Permission: rbac.UsersManage, Order: 80},
	}
}
func (testModule) Templates() fs.FS {
	return fstest.MapFS{"build.html": {Data: []byte(`{{define "content"}}<p id="b">{{.Data}}</p>{{end}}`)}}
}

type env struct {
	srv    *httptest.Server
	mgr    *jobs.Manager
	mu     sync.Mutex
	audits []audit.Event
}

func newEnv(t *testing.T, authn auth.Authenticator, modules ...Module) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "web.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	e := &env{mgr: jobs.New(db, jobs.Options{Workers: 1, PollInterval: 10 * time.Millisecond})}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	_ = e.mgr.Register("test.echo", jobs.HandlerFunc(func(ctx context.Context, j *jobs.Job, log *jobs.LogWriter) (any, error) {
		log.Printf("hello from job")
		return map[string]string{"ok": "yes"}, nil
	}))
	_ = e.mgr.Register("test.block", jobs.HandlerFunc(func(ctx context.Context, j *jobs.Job, log *jobs.LogWriter) (any, error) {
		select {
		case <-ctx.Done():
		case <-release:
		}
		return nil, ctx.Err()
	}))
	if err := e.mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.mgr.Stop(c)
	})
	s := NewServer(Options{
		Jobs: e.mgr, Version: "test", HSTS: true,
		Audit: audit.RecorderFunc(func(_ context.Context, ev audit.Event) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.audits = append(e.audits, ev)
			return nil
		}),
	})
	s.SetAuthenticator(authn)
	s.AddReadinessCheck("db", func(ctx context.Context) error { return db.PingContext(ctx) })
	for _, m := range modules {
		s.AddModule(m)
	}
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(t *testing.T, method, path, role string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	if role != "" {
		req.Header.Set("X-Test-Role", role)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestHealthAndStatic(t *testing.T) {
	e := newEnv(t, auth.DenyAll{})
	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{"/healthz", 200, "ok"},
		{"/readyz", 200, `"ready"`},
		{"/static/app.css", 200, "--accent"},
		{"/static/htmx.min.js", 200, "htmx"},
		{"/", 401, "Sign-in required"},
		{"/jobs", 401, "Sign-in required"},
		{"/nope", 404, ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			resp, body := e.do(t, "GET", tt.path, "")
			if resp.StatusCode != tt.wantStatus || !strings.Contains(body, tt.wantBody) {
				t.Fatalf("GET %s = %d %q", tt.path, resp.StatusCode, body)
			}
		})
	}
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	e := newEnv(t, auth.DenyAll{})
	resp, _ := e.do(t, "GET", "/healthz", "", "X-Request-ID", "abc-123")
	for k, want := range map[string]string{
		"Content-Security-Policy":   "default-src 'self'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=",
		"X-Request-Id":              "abc-123",
	} {
		if got := resp.Header.Get(k); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	resp, _ = e.do(t, "GET", "/healthz", "", "X-Request-ID", "bad id <script>")
	if got := resp.Header.Get("X-Request-ID"); got == "" || strings.Contains(got, "<") {
		t.Errorf("unsafe request id propagated: %q", got)
	}
}

func TestAuthorization(t *testing.T) {
	e := newEnv(t, headerAuth{}, testModule{})
	id, err := e.mgr.Enqueue(context.Background(), "test.block", nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		method     string
		path       string
		role       string
		hdr        []string
		wantStatus int
		wantBody   string
	}{
		{"unauth redirect to login", "GET", "/jobs", "", nil, 303, ""},
		{"unauth htmx gets 401", "GET", "/jobs", "", []string{"HX-Request", "true"}, 401, ""},
		{"viewer dashboard", "GET", "/", rbac.RoleViewer, nil, 200, "Recent jobs"},
		{"viewer jobs", "GET", "/jobs", rbac.RoleViewer, nil, 200, "test.block"},
		{"viewer jobs partial", "GET", "/jobs", rbac.RoleViewer, []string{"HX-Request", "true"}, 200, "test.block"},
		{"viewer bad filter", "GET", "/jobs?status=bogus", rbac.RoleViewer, nil, 400, ""},
		{"viewer job detail", "GET", "/jobs/" + id, rbac.RoleViewer, nil, 200, "job-log"},
		{"viewer no cancel button", "GET", "/jobs/" + id, rbac.RoleViewer, nil, 200, ""},
		{"missing job", "GET", "/jobs/missing", rbac.RoleViewer, nil, 404, ""},
		{"viewer cannot cancel", "POST", "/jobs/" + id + "/cancel", rbac.RoleViewer, nil, 403, ""},
		{"viewer cannot see audit", "GET", "/audit", rbac.RoleViewer, nil, 403, ""},
		{"admin placeholder", "GET", "/audit", rbac.RoleAdmin, nil, 200, "not available yet"},
		{"module page", "GET", "/build", rbac.RoleViewer, nil, 200, `<p id="b">hello-build</p>`},
		{"public login", "GET", "/login", "", nil, 200, "login page"},
		{"panic recovered", "GET", "/boom", rbac.RoleViewer, nil, 500, ""},
		{"cross-origin post blocked", "POST", "/jobs/" + id + "/cancel", rbac.RoleAdmin, []string{"Sec-Fetch-Site", "cross-site"}, 403, ""},
		{"admin cancel", "POST", "/jobs/" + id + "/cancel", rbac.RoleAdmin, []string{"Sec-Fetch-Site", "same-origin"}, 303, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do(t, tt.method, tt.path, tt.role, tt.hdr...)
			if resp.StatusCode != tt.wantStatus || !strings.Contains(body, tt.wantBody) {
				t.Fatalf("%s %s = %d, body %q", tt.method, tt.path, resp.StatusCode, body)
			}
			if tt.name == "viewer no cancel button" && strings.Contains(body, "Cancel job") {
				t.Error("viewer sees cancel button")
			}
			if tt.name == "unauth redirect to login" && !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
				t.Errorf("Location = %q", resp.Header.Get("Location"))
			}
		})
	}
	var denied, canceled bool
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.audits {
		denied = denied || (ev.Action == "authz.deny" && ev.Outcome == audit.OutcomeDenied)
		canceled = canceled || (ev.Action == "job.cancel" && ev.Outcome == audit.OutcomeSuccess && ev.Actor == "admin")
	}
	if !denied || !canceled {
		t.Errorf("audit events missing: %+v", e.audits)
	}
}

func TestNavFilteringAndOverride(t *testing.T) {
	e := newEnv(t, headerAuth{}, testModule{})
	_, body := e.do(t, "GET", "/", rbac.RoleViewer, nil...)
	for _, want := range []string{">Dashboard<", ">Images<", ">Jobs<", ">Deploy<"} {
		if !strings.Contains(body, want) {
			t.Errorf("viewer nav missing %s", want)
		}
	}
	for _, hidden := range []string{">Build<", ">Audit<", ">Settings<", ">Extra<"} {
		if strings.Contains(body, hidden) {
			t.Errorf("viewer nav shows %s", hidden)
		}
	}
	_, body = e.do(t, "GET", "/", rbac.RoleAdmin, nil...)
	if !strings.Contains(body, ">Extra<") || !strings.Contains(body, ">Settings<") {
		t.Error("admin nav incomplete")
	}
}

func TestJobStreamSSE(t *testing.T) {
	e := newEnv(t, headerAuth{})
	id, _ := e.mgr.Enqueue(context.Background(), "test.echo", nil, "")
	req, _ := http.NewRequest("GET", e.srv.URL+"/jobs/"+id+"/stream", nil)
	req.Header.Set("X-Test-Role", rbac.RoleViewer)
	req.Header.Set("Accept", "text/event-stream")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	var sawLog, sawDone bool
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "hello from job") {
			sawLog = true
		}
		if line == "event: done" {
			sawDone = true
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !sawLog || !sawDone {
		t.Fatalf("stream log=%v done=%v", sawLog, sawDone)
	}
}

func TestDuplicateModule(t *testing.T) {
	s := NewServer(Options{})
	s.AddModule(testModule{})
	s.AddModule(testModule{})
	if _, err := s.Handler(); err == nil {
		t.Fatal("duplicate module accepted")
	}
}

func TestPatternPath(t *testing.T) {
	tests := map[string]string{
		"GET /{$}":          "/",
		"GET /jobs":         "/jobs",
		"POST /jobs/{id}":   "/jobs/{id}",
		"/static/":          "/static/",
		"GET example.com/x": "/x",
	}
	for in, want := range tests {
		if got := patternPath(in); got != want {
			t.Errorf("patternPath(%q) = %q, want %q", in, got, want)
		}
	}
}
