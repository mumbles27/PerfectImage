package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type testPlugin struct {
	shutdown *bool
}

func (testPlugin) Name() string { return "test" }

func (p testPlugin) Init(_ context.Context, d *Deps) error {
	if err := d.Jobs.Register("test.noop", jobs.HandlerFunc(func(context.Context, *jobs.Job, *jobs.LogWriter) (any, error) {
		return nil, nil
	})); err != nil {
		return err
	}
	d.Web.AddModule(pluginModule{})
	d.OnShutdown(func(context.Context) error { *p.shutdown = true; return nil })
	return nil
}

type pluginModule struct{}

func (pluginModule) Name() string { return "plugin" }
func (pluginModule) Routes(rt *web.Router) {
	rt.HandleFunc("GET /deploy", rbac.DeployView, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "deploy-from-plugin")
	})
}
func (pluginModule) Nav() []web.NavItem { return nil }

func testConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	y := "data_dir: ./data\nserver: {listen: '127.0.0.1:0', shutdown_timeout: 5s}\nlog: {level: debug}\n" + extra
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAppRunTLSAndShutdown(t *testing.T) {
	cfg := testConfig(t, "auth: {dev_allow_all: true}\n")
	var shutdown bool
	logs := &syncBuffer{}
	a, err := New(context.Background(), cfg, Options{Version: "test", Stdout: logs, Plugins: []Plugin{testPlugin{&shutdown}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for a.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a.Addr() == nil {
		t.Fatal("server did not start")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed test cert
	}}
	base := "https://" + a.Addr().String()
	tests := []struct {
		path string
		want string
	}{
		{"/healthz", "ok"},
		{"/readyz", `"jobs":"ok"`},
		{"/", "Dashboard"},
		{"/deploy", "deploy-from-plugin"},
		{"/jobs", "Jobs"},
	}
	for _, tt := range tests {
		resp, err := client.Get(base + tt.path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), tt.want) {
			t.Errorf("GET %s = %d %q", tt.path, resp.StatusCode, b)
		}
		if resp.Header.Get("Strict-Transport-Security") == "" {
			t.Errorf("GET %s: missing HSTS", tt.path)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if !shutdown {
		t.Error("OnShutdown hook not called")
	}
	for _, f := range []string{"perfectimage.db", "tls/selfsigned.crt", "logs/perfectimage.log"} {
		fi, err := os.Stat(filepath.Join(cfg.DataDir, f))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if runtime.GOOS != "windows" && strings.HasSuffix(f, ".db") && fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s perms %v", f, fi.Mode().Perm())
		}
	}
	if !strings.Contains(logs.String(), `"msg":"shutdown complete"`) {
		t.Error("missing shutdown log")
	}
}

func TestNewPluginError(t *testing.T) {
	cfg := testConfig(t, "")
	_, err := New(context.Background(), cfg, Options{Stdout: io.Discard, Plugins: []Plugin{failingPlugin{}}})
	if err == nil || !strings.Contains(err.Error(), "plugin failing") {
		t.Fatalf("err = %v", err)
	}
}

type failingPlugin struct{}

func (failingPlugin) Name() string                      { return "failing" }
func (failingPlugin) Init(context.Context, *Deps) error { return io.ErrUnexpectedEOF }

func TestServiceConfig(t *testing.T) {
	c := ServiceConfig("/etc/perfectimage/config.yaml")
	if c.Name != ServiceName || strings.Join(c.Arguments, " ") != "serve --config /etc/perfectimage/config.yaml" {
		t.Fatalf("ServiceConfig = %+v", c)
	}
}
