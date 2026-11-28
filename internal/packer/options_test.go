package packer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/catalog"
)

func TestOptionsValidation(t *testing.T) {
	c := embeddedCatalog(t)
	base := func(image string) BuildRequest {
		r := BuildRequest{ImageID: image, Cluster: "lab", Node: "pve1", TemplateName: "t1"}
		if image != "ubuntu-24.04" && image != "rocky-9" {
			r.ISOFile = "local:iso/win.iso"
		}
		return r
	}
	tests := []struct {
		name     string
		image    string
		settings OSSettings
		post     PostScript
		badField string // "" = valid
	}{
		{"linux all settings", "ubuntu-24.04", OSSettings{Timezone: "America/Chicago", Locale: "de-DE", Keyboard: "de", Updates: true}, PostScript{}, ""},
		{"linux utc", "rocky-9", OSSettings{Timezone: "UTC", Locale: "en_US.UTF-8", Keyboard: "us-intl"}, PostScript{}, ""},
		{"linux windows zone", "ubuntu-24.04", OSSettings{Timezone: "Pacific Standard Time"}, PostScript{}, "timezone"},
		{"linux zone injection", "ubuntu-24.04", OSSettings{Timezone: "Europe/Berlin; rm -rf /"}, PostScript{}, "timezone"},
		{"bad locale", "ubuntu-24.04", OSSettings{Locale: "english"}, PostScript{}, "locale"},
		{"linux bad keyboard", "ubuntu-24.04", OSSettings{Keyboard: "DE'"}, PostScript{}, "keyboard"},
		{"linux edition", "ubuntu-24.04", OSSettings{WindowsEdition: "Windows Server 2025 SERVERSTANDARD"}, PostScript{}, "windows_edition"},
		{"windows all settings", "windows-server-2025", OSSettings{Timezone: "W. Europe Standard Time", Locale: "de-DE", Keyboard: "0407:00000407",
			Updates: true, WindowsEdition: "Windows Server 2025 SERVERDATACENTER"}, PostScript{Script: "Write-Host hi", Reboot: true}, ""},
		{"windows iana zone", "windows-server-2025", OSSettings{Timezone: "Europe/Berlin"}, PostScript{}, "timezone"},
		{"windows xkb keyboard", "windows-11", OSSettings{Keyboard: "de"}, PostScript{}, "keyboard"},
		{"windows edition markup", "windows-server-2022", OSSettings{WindowsEdition: "<Edition>"}, PostScript{}, "windows_edition"},
		{"post script too big", "ubuntu-24.04", OSSettings{}, PostScript{Script: strings.Repeat("x", MaxPostScriptBytes+1)}, "post_script"},
		{"post script nul", "ubuntu-24.04", OSSettings{}, PostScript{Script: "echo\x00"}, "post_script"},
		{"reboot without script", "ubuntu-24.04", OSSettings{}, PostScript{Script: "  \n", Reboot: true}, "post_script"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base(tt.image)
			r.Settings, r.PostScript = tt.settings, tt.post
			_, _, err := r.Check(c)
			if tt.badField == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			fe, ok := err.(FieldErrors)
			if !ok || fe[tt.badField] == "" {
				t.Fatalf("want error on %q, got %v", tt.badField, err)
			}
		})
	}
}

func TestStepsOrderAndKinds(t *testing.T) {
	c := embeddedCatalog(t)
	r := BuildRequest{ImageID: "windows-server-2025", Cluster: "lab", Node: "pve1", TemplateName: "t1",
		Settings:   OSSettings{Timezone: "UTC", Locale: "en-GB", Updates: true},
		PostScript: PostScript{Script: "Write-Host done\r\n", Reboot: true}}
	img, apps, err := r.Check(c)
	if err != nil {
		t.Fatal(err)
	}
	steps := r.Steps(img, apps)
	var ids []string
	for _, s := range steps {
		ids = append(ids, s.AppID)
	}
	want := []string{"_os-settings", "_os-updates-1", "_os-updates-2", "_os-updates-3", "7zip", "_post-install"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("steps %v, want %v", ids, want)
	}
	for _, s := range steps {
		if s.Shell != catalog.ShellPowerShell {
			t.Fatalf("%s: shell %q", s.AppID, s.Shell)
		}
		if strings.HasPrefix(s.AppID, "_os-updates") != s.Elevated {
			t.Fatalf("%s: elevated=%t", s.AppID, s.Elevated)
		}
		if isAppStep(s) != (s.AppID == "7zip") {
			t.Fatalf("isAppStep(%s)", s.AppID)
		}
	}
	if !steps[0].RebootRequired || !steps[5].RebootRequired {
		t.Fatal("locale change and post script should reboot")
	}
	if steps[5].Script != "Write-Host done\n" {
		t.Fatalf("post script not normalized: %q", steps[5].Script)
	}
	if !strings.Contains(steps[0].Script, WindowsSettingsFile) || !strings.Contains(steps[0].Script, "'en-GB'") {
		t.Fatalf("settings script:\n%s", steps[0].Script)
	}

	prov := Provisioners(catalog.Windows, steps, "")
	if strings.Count(prov, "elevated_user     = var.build_username") != 3 || strings.Count(prov, `"windows-restart"`) != 5 {
		t.Fatalf("provisioners:\n%s", prov)
	}

	// No options: only the app steps.
	plain := BuildRequest{ImageID: "ubuntu-24.04"}
	img = c.Images["ubuntu-24.04"]
	if got := plain.Steps(img, apps); len(got) != len(apps) {
		t.Fatalf("plain steps = %d", len(got))
	}
}

func TestLinuxOptionScripts(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	c := embeddedCatalog(t)
	for _, image := range []string{"ubuntu-24.04", "debian-13", "rocky-9"} {
		t.Run(image, func(t *testing.T) {
			r := BuildRequest{ImageID: image, Settings: OSSettings{Timezone: "America/Chicago", Locale: "de-DE", Keyboard: "us-intl", Updates: true},
				PostScript: PostScript{Script: "echo hi"}}
			img := c.Images[image]
			steps := r.Steps(img, nil)
			if len(steps) != 3 || steps[0].AppID != stepSettings || steps[1].AppID != stepUpdates || !steps[1].RebootRequired {
				t.Fatalf("steps %+v", steps)
			}
			s := steps[0].Script
			for _, want := range []string{"tz='America/Chicago'", "loc='de_DE.UTF-8'", "kb='us'", "kbv='intl'"} {
				if !strings.Contains(s, want) {
					t.Fatalf("settings script lacks %q:\n%s", want, s)
				}
			}
			pkg := "apt-get"
			if img.DistroFamily == catalog.DistroRHEL {
				pkg = "dnf"
			}
			if !strings.Contains(steps[1].Script, pkg) || !strings.Contains(s, map[bool]string{true: "dnf", false: "locale-gen"}[pkg == "dnf"]) {
				t.Fatalf("wrong package manager for %s", image)
			}
			for _, st := range steps[:2] {
				f := filepath.Join(t.TempDir(), "s.sh")
				if err := os.WriteFile(f, []byte(st.Script), 0o600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
					t.Fatalf("%s: bash -n: %v\n%s\n%s", st.AppID, err, out, st.Script)
				}
			}
		})
	}
}

// TestWindowsScriptsParse parses the generated PowerShell and the catalog's
// sysprep.ps1 with the real parser when pwsh is available.
func TestWindowsScriptsParse(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not found")
	}
	r := BuildRequest{Settings: OSSettings{Timezone: "W. Europe Standard Time", Locale: "de-DE", Keyboard: "de-DE", Updates: true}}
	img := &catalog.Image{OSFamily: catalog.Windows}
	dir := t.TempDir()
	var files []string
	for i, st := range r.Steps(img, nil) {
		f := filepath.Join(dir, st.AppID+".ps1")
		if err := os.WriteFile(f, []byte(st.Script), 0o600); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			files = append(files, f)
		}
	}
	files = append(files, filepath.Join("..", "..", "catalog", "images", "windows-server-2025", "scripts", "sysprep.ps1"))
	for _, f := range files {
		abs, _ := filepath.Abs(f)
		cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command",
			`$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:PI_PARSE_FILE,[ref]$null,[ref]$e); if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 }`)
		cmd.Env = append(os.Environ(), "PI_PARSE_FILE="+abs)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s does not parse: %v\n%s", f, err, out)
		}
	}
}
