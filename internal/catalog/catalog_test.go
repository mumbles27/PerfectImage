package catalog

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const gitApp = `id: git
name: Git
category: dev
install:
  windows:
    - winget:
        id: Git.Git
      verify: 'exit 0'
  linux:
    - apt:
        packages: [git]
      verify: command -v git
    - dnf:
        packages: [git]
      verify: command -v git
`

func mapFS(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for k, v := range files {
		m[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return m
}

func load(t *testing.T, layers ...Layer) *Catalog {
	t.Helper()
	c, err := Load(context.Background(), layers...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseProblems(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		body     string
		wantLine int
		wantMsg  string
	}{
		{"unknown field", "apps/a.yaml", "id: a\nname: A\ncategory: dev\nbogus: 1\n", 4, "field bogus not found"},
		{"syntax error", "apps/a.yaml", "id: a\nname: [\n", 2, "did not find"},
		{"bad category", "apps/a.yaml", "id: a\nname: A\ncategory: games\ninstall:\n  linux:\n    - shell: {script: 'true'}\n      verify: 'true'\n", 3, "category"},
		{"method missing", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - verify: x\n", 6, "method must set one of"},
		{"two methods", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - apt: {packages: [a]}\n      dnf: {packages: [a]}\n      verify: x\n", 6, "more than one"},
		{"windows kind on linux", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - winget: {id: A.B}\n      verify: x\n", 6, "not a linux install method"},
		{"missing verify", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - apt: {packages: [a]}\n", 6, "verify is required"},
		{"bad package", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - apt:\n        packages: ['a; rm -rf /']\n      verify: x\n", 7, "invalid format"},
		{"bad sha", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  windows:\n    - msi:\n        url: https://example.com/a.msi\n        sha256: abc\n      verify: x\n", 8, "invalid format"},
		{"tarball dest", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - tarball:\n        url: https://example.com/a.tgz\n        sha256: " + strings.Repeat("a", 64) + "\n        dest: /etc\n      verify: x\n", 9, "below /opt or /usr/local"},
		{"id mismatch", "apps/b.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - shell: {script: 'true'}\n      verify: 'true'\n", 1, "must match the file name"},
		{"apt repo url quotes", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ninstall:\n  linux:\n    - apt:\n        packages: [a]\n        repo: {name: r, url: 'https://x/\"', key_url: 'https://x/k', suite: stable}\n      verify: x\n", 8, "https URL"},
		{"bundle unknown app", "bundles/b.yaml", "id: b\nname: B\napps: [git, nope]\n", 3, `unknown app "nope"`},
		{"dependency missing", "apps/a.yaml", "id: a\nname: A\ncategory: dev\ndepends_on: [ghost]\ninstall:\n  linux:\n    - shell: {script: 'true'}\n      verify: 'true'\n", 4, `unknown dependency "ghost"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := load(t, Layer{Origin: "/o", FS: mapFS(map[string]string{"apps/git.yaml": gitApp, tt.file: tt.body})})
			var found bool
			for _, p := range c.Problems {
				if p.File == filepath.Join("/o", tt.file) && p.Line == tt.wantLine && strings.Contains(p.Message, tt.wantMsg) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want problem %s:%d %q, got %v", tt.file, tt.wantLine, tt.wantMsg, c.Problems)
			}
		})
	}
}

func TestMergeOverridesWinByID(t *testing.T) {
	base := Layer{Origin: OriginEmbedded, FS: mapFS(map[string]string{
		"apps/git.yaml":    gitApp,
		"bundles/dev.yaml": "id: dev\nname: Dev\napps: [git]\n",
	})}
	over := Layer{Origin: "/override", FS: mapFS(map[string]string{
		"apps/git.yaml": strings.Replace(gitApp, "name: Git", "name: Git (pinned)", 1),
	})}
	c := load(t, base, over)
	if len(c.Problems) > 0 {
		t.Fatalf("problems: %v", c.Problems)
	}
	g := c.Apps["git"]
	if g.Name != "Git (pinned)" || g.Source.Origin != "/override" || g.Source.Embedded() {
		t.Fatalf("override did not win: %+v", g)
	}
	if c.Bundles["dev"].Source.Origin != OriginEmbedded {
		t.Fatal("bundle should come from the base layer")
	}
}

func appYAML(id string, deps ...string) string {
	return "id: " + id + "\nname: " + id + "\ncategory: dev\ndepends_on: [" + strings.Join(deps, ", ") + "]\n" +
		"install:\n  linux:\n    - apt: {packages: [" + id + "]}\n      verify: command -v " + id + "\n"
}

func TestResolve(t *testing.T) {
	fs := mapFS(map[string]string{
		"apps/a.yaml":      appYAML("a", "b", "c"),
		"apps/b.yaml":      appYAML("b", "c"),
		"apps/c.yaml":      appYAML("c"),
		"apps/x.yaml":      appYAML("x", "y"),
		"apps/y.yaml":      appYAML("y", "x"),
		"apps/git.yaml":    gitApp,
		"bundles/bun.yaml": "id: bun\nname: Bun\napps: [c, git]\n",
	})
	c := load(t, Layer{Origin: "/o", FS: fs})
	var cyc bool
	for _, p := range c.Problems {
		cyc = cyc || strings.Contains(p.Message, "dependency cycle")
	}
	if !cyc {
		t.Fatalf("cycle not reported: %v", c.Problems)
	}
	tests := []struct {
		name    string
		os      OSFamily
		distro  string
		ids     []string
		want    []string
		wantErr error
	}{
		{"deps first", Linux, DistroDebian, []string{"a"}, []string{"c", "b", "a"}, nil},
		{"dedupe and bundle", Linux, DistroDebian, []string{"bun", "a", "c"}, []string{"c", "git", "b", "a"}, nil},
		{"cycle", Linux, DistroDebian, []string{"x"}, nil, ErrCycle},
		{"unknown", Linux, DistroDebian, []string{"nope"}, nil, ErrUnknownApp},
		{"apt only on rhel", Linux, DistroRHEL, []string{"c"}, nil, ErrUnsupported},
		{"windows", Windows, "", []string{"git"}, []string{"git"}, nil},
		{"no windows method", Windows, "", []string{"c"}, nil, ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			steps, err := c.Resolve(tt.os, tt.distro, tt.ids)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, s := range steps {
				got = append(got, s.AppID)
				wantShell := ShellBash
				if tt.os == Windows {
					wantShell = ShellPowerShell
				}
				if s.Shell != wantShell || s.Script == "" || s.VerifyScript == "" {
					t.Fatalf("bad step %+v", s)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("order = %v, want %v", got, tt.want)
			}
		})
	}
	if _, err := c.Resolve("plan9", "", []string{"git"}); err == nil {
		t.Fatal("unknown os accepted")
	}
}

func TestScriptsQuoteValues(t *testing.T) {
	a := &App{ID: "q", Name: "Q", Install: Install{Linux: []Method{{Shell: &Script{Script: "echo 'it''s'"}, Verify: "test -e '/x y'"}}}}
	s := Step(a, Linux, DistroDebian)
	if !strings.Contains(s.Script, `'test -e '\''/x y'\'''`) {
		t.Fatalf("verify not shell-quoted:\n%s", s.Script)
	}
	w := &App{ID: "w", Name: "W", Install: Install{Windows: []Method{{Choco: &Choco{Package: "o'brien"}, Verify: "exit 0"}}}}
	ps := Step(w, Windows, "")
	if !strings.Contains(ps.Script, "install 'o''brien'") {
		t.Fatalf("choco package not quoted:\n%s", ps.Script)
	}
	if !strings.Contains(ps.Script, psEncode("exit 0")) {
		t.Fatal("verify not encoded")
	}
}

// TestEmbeddedCatalog checks the shipped catalog is valid and every
// generated bash script parses.
func TestEmbeddedCatalog(t *testing.T) {
	c := load(t, Layer{Origin: OriginEmbedded, FS: EmbeddedFS()})
	for _, p := range c.Problems {
		t.Errorf("%s", p)
	}
	if len(c.Images) < 6 || len(c.Apps) < 30 || len(c.Bundles) < 3 {
		t.Fatalf("catalog too small: %d images, %d apps, %d bundles", len(c.Images), len(c.Apps), len(c.Bundles))
	}
	for _, id := range []string{"windows-server-2022", "windows-server-2025", "windows-11", "ubuntu-24.04", "debian-13", "rocky-9"} {
		if c.Images[id] == nil {
			t.Errorf("missing starter image %s", id)
		}
	}
	if !c.Images["windows-11"].TPM || c.Images["windows-11"].Firmware != "uefi" {
		t.Error("windows-11 must be UEFI + TPM")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	for _, distro := range []string{DistroDebian, DistroRHEL} {
		var ids []string
		for _, a := range c.AppList() {
			if a.Supports(Linux, distro) {
				ids = append(ids, a.ID)
			}
		}
		steps, err := c.Resolve(Linux, distro, ids)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range steps {
			for name, body := range map[string]string{"install": s.Script, "verify": s.VerifyScript} {
				f := filepath.Join(dir, distro+"-"+s.AppID+"-"+name+".sh")
				if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
					t.Errorf("%s/%s %s: %s", distro, s.AppID, name, out)
				}
			}
		}
	}
}

func TestStoreHotReloadAndEditor(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := NewStore(mapFS(map[string]string{"apps/git.yaml": gitApp}), []string{dir}, nil)
	if changed, err := s.Reload(ctx, false); err != nil || !changed {
		t.Fatalf("first reload: %v %v", changed, err)
	}
	if changed, _ := s.Reload(ctx, false); changed {
		t.Fatal("reload without changes reported a change")
	}

	// A file dropped into the override dir is picked up by polling.
	if err := os.MkdirAll(filepath.Join(dir, "apps"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "apps", "jq.yaml"), []byte(appYAML("jq")), 0o600); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithCancel(ctx)
	go s.Watch(wctx, 10*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for s.Catalog().Apps["jq"] == nil {
		if time.Now().After(deadline) {
			t.Fatal("hot reload did not pick up jq")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	tests := []struct {
		name     string
		kind     Kind
		mode     string
		orig     string
		body     string
		wantErr  error
		wantProb string
	}{
		{"create clashes", KindApp, ModeCreate, "", gitApp, ErrInvalid, "already exists"},
		{"edit renames", KindApp, ModeEdit, "jq", appYAML("jq2"), ErrInvalid, "cannot change"},
		{"invalid yaml", KindApp, ModeCreate, "", "id: z\nname: [", ErrInvalid, ""},
		{"bundle unknown app", KindBundle, ModeCreate, "", "id: tools\nname: T\napps: [nope]\n", ErrInvalid, "unknown app"},
		{"bundle id clashes with app", KindBundle, ModeCreate, "", "id: jq\nname: T\napps: [git]\n", ErrInvalid, "already used by a app"},
		{"cycle via edit", KindApp, ModeEdit, "jq", appYAML("jq", "jq"), ErrInvalid, "itself"},
		{"edit embedded creates override", KindApp, ModeEdit, "git", strings.Replace(gitApp, "name: Git", "name: Git2", 1), nil, ""},
		{"create bundle", KindBundle, ModeCreate, "", "id: tools\nname: Tools\napps: [git, jq]\n", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := s.Save(ctx, tt.kind, []byte(tt.body), tt.mode, tt.orig)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v (problems %v)", err, tt.wantErr, res.Problems)
			}
			if tt.wantProb != "" {
				var ok bool
				for _, p := range res.Problems {
					ok = ok || strings.Contains(p.Message, tt.wantProb)
				}
				if !ok {
					t.Fatalf("problems %v do not mention %q", res.Problems, tt.wantProb)
				}
			}
		})
	}
	c := s.Catalog()
	if c.Apps["git"].Name != "Git2" || !s.IsOverride(c.Apps["git"].Source) {
		t.Fatalf("git override not applied: %+v", c.Apps["git"])
	}
	if c.Bundles["tools"] == nil {
		t.Fatal("bundle not saved")
	}
	if fi, err := os.Stat(filepath.Join(dir, "bundles", "tools.yaml")); err != nil || (fi.Mode().Perm()&0o007 != 0 && !isWindows()) {
		t.Fatalf("bundle file: %v %v", fi, err)
	}
	raw, err := s.Raw(KindApp, "git")
	if err != nil || !strings.Contains(string(raw), "Git2") {
		t.Fatalf("raw = %q, %v", raw, err)
	}
	if _, err := s.DeleteOverride(ctx, KindApp, "git"); err != nil {
		t.Fatal(err)
	}
	if got := s.Catalog().Apps["git"]; got.Name != "Git" || !got.Source.Embedded() {
		t.Fatalf("revert did not restore embedded git: %+v", got)
	}
	if _, err := s.DeleteOverride(ctx, KindApp, "git"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestDirValidator(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "apps"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "apps", "bad.yaml"), []byte("id: bad\nname: Bad\ncategory: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probs, err := DirValidator{}.Validate(context.Background(), []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(probs) == 0 || probs[0].File != filepath.Join(dir, "apps", "bad.yaml") || probs[0].Line == 0 {
		t.Fatalf("problems = %v", probs)
	}
	if !strings.Contains(probs[0].String(), "bad.yaml:") {
		t.Fatalf("String() = %q", probs[0].String())
	}
}
