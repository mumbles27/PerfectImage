package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/deploy"
)

func embeddedResolver(t *testing.T) *CatalogResolver {
	t.Helper()
	s := catalog.NewStore(catalog.EmbeddedFS(), nil, nil)
	if _, err := s.Reload(context.Background(), true); err != nil {
		t.Fatalf("load embedded catalog: %v", err)
	}
	return &CatalogResolver{Catalog: s.Catalog}
}

// bashSyntax checks script with `bash -n` when bash is available.
func bashSyntax(t *testing.T, name, script string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		return
	}
	f := filepath.Join(t.TempDir(), "s.sh")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
		t.Errorf("%s: bash -n: %v\n%s\n--- script ---\n%s", name, err, out, script)
	}
}

func TestResolveLinux(t *testing.T) {
	r := embeddedResolver(t)
	tests := []struct {
		name string
		ids  []string
	}{
		{"single app", []string{"git"}},
		{"several apps", []string{"git", "jq", "tmux", "vscode", "docker"}},
		{"bundle", []string{"developer-base"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps, err := r.Resolve(context.Background(), deploy.OSLinux, tt.ids)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(steps) == 0 {
				t.Fatal("no steps")
			}
			for _, s := range steps {
				if err := s.Validate(); err != nil {
					t.Errorf("step invalid: %v", err)
				}
				if s.Shell != deploy.ShellBash {
					t.Errorf("%s: shell = %q", s.Name, s.Shell)
				}
				if !strings.Contains(s.Script, "command -v apt-get") || !strings.Contains(s.Script, "command -v dnf") {
					t.Errorf("%s: script lacks distro dispatch", s.Name)
				}
				bashSyntax(t, s.Name+" install", s.Script)
				if s.VerifyScript != "" {
					bashSyntax(t, s.Name+" verify", s.VerifyScript)
				}
			}
		})
	}
}

func TestResolveWindows(t *testing.T) {
	r := embeddedResolver(t)
	steps, err := r.Resolve(context.Background(), deploy.OSWindows, []string{"git", "7zip", "browsers"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(steps) < 3 {
		t.Fatalf("steps = %d, want >= 3", len(steps))
	}
	for _, s := range steps {
		if err := s.Validate(); err != nil {
			t.Errorf("step invalid: %v", err)
		}
		if s.Shell != deploy.ShellPowerShell {
			t.Errorf("%s: shell = %q", s.Name, s.Shell)
		}
	}
}

func TestResolveErrors(t *testing.T) {
	r := embeddedResolver(t)
	if _, err := r.Resolve(context.Background(), deploy.OSLinux, []string{"no-such-app"}); !errors.Is(err, deploy.ErrUnknownApp) {
		t.Errorf("unknown app: err = %v, want deploy.ErrUnknownApp", err)
	}
	if _, err := r.Resolve(context.Background(), "bsd", []string{"git"}); err == nil {
		t.Error("unknown OS: want error")
	}
	// Windows-only app on Linux.
	if _, err := r.Resolve(context.Background(), deploy.OSLinux, []string{"windows-terminal"}); err == nil {
		t.Error("windows-only app on linux: want error")
	}
	if steps, err := r.Resolve(context.Background(), deploy.OSLinux, nil); err != nil || steps != nil {
		t.Errorf("empty: steps=%v err=%v", steps, err)
	}
}

func TestApps(t *testing.T) {
	r := embeddedResolver(t)
	for _, osName := range []string{deploy.OSLinux, deploy.OSWindows} {
		apps, err := r.Apps(context.Background(), osName)
		if err != nil {
			t.Fatalf("%s: %v", osName, err)
		}
		if len(apps) < 10 {
			t.Errorf("%s: only %d apps listed", osName, len(apps))
		}
		ids := map[string]bool{}
		for _, a := range apps {
			ids[a.ID] = true
		}
		if !ids["git"] {
			t.Errorf("%s: git missing", osName)
		}
		if osName == deploy.OSLinux && ids["windows-terminal"] {
			t.Error("linux list contains windows-terminal")
		}
	}
}

func TestSubshellDispatchRuns(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	var b strings.Builder
	b.WriteString("if true; then\n")
	writeSubshell(&b, "set -e\necho hi\nexit 7")
	b.WriteString("fi\necho unreachable\n")
	out, err := exec.Command(bash, "-c", b.String()).Output()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("exit = %v, want 7", err)
	}
	if strings.TrimSpace(string(out)) != "hi" {
		t.Errorf("output = %q", out)
	}
}
