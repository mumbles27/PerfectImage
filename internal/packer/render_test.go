package packer

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/catalog"
)

var update = flag.Bool("update", false, "update golden files")

func embeddedCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load(context.Background(), catalog.Layer{Origin: catalog.OriginEmbedded, FS: catalog.EmbeddedFS()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s mismatch (run go test ./internal/packer -run TestRenderGolden -update):\n--- got ---\n%s", name, got)
	}
}

func TestRenderGolden(t *testing.T) {
	c := embeddedCatalog(t)
	tests := []struct {
		name string
		req  BuildRequest
	}{
		{"ubuntu", BuildRequest{ImageID: "ubuntu-24.04", Cluster: "lab", Node: "pve1", TemplateName: "ubuntu-golden",
			Apps: []string{"git", "docker"}, Cores: 4, Storage: "ceph"}},
		{"windows-11", BuildRequest{ImageID: "windows-11", Cluster: "lab", Node: "pve1", TemplateName: "win11-golden",
			VMID: 9100, Apps: []string{"docker", "7zip"}, ISOFile: "local:iso/Win11_24H2.iso"}},
		{"rocky-iso-file", BuildRequest{ImageID: "rocky-9", Cluster: "lab", Node: "pve1", TemplateName: "rocky-golden",
			SkipDefaultApps: true, ISOFile: "local:iso/rocky.iso"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, steps, err := tt.req.Check(c)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "w")
			vars := Vars(img, tt.req, true, "golden build")
			if err := Render(dir, img, steps, vars); err != nil {
				t.Fatal(err)
			}
			build, err := os.ReadFile(filepath.Join(dir, "build.pkr.hcl"))
			if err != nil {
				t.Fatal(err)
			}
			golden(t, tt.name+".build.pkr.hcl", build)
			vb, err := os.ReadFile(filepath.Join(dir, VarsFile))
			if err != nil {
				t.Fatal(err)
			}
			golden(t, tt.name+".pkrvars.hcl", vb)
			if strings.Contains(string(build), catalog.AppsMarker) {
				t.Fatal("marker not replaced")
			}
			fi, err := os.Stat(filepath.Join(dir, VarsFile))
			if err != nil {
				t.Fatal(err)
			}
			if perm := fi.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
				t.Fatalf("vars file mode %v, want 0600", perm)
			}
			for i, s := range steps {
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(AppsDir), stepFile(i, s))); err != nil {
					t.Fatalf("step script: %v", err)
				}
			}
		})
	}
}

// TestRenderedTemplatesValidate runs `packer validate` on every rendered
// starter image when PERFECTIMAGE_PACKER_VALIDATE=1 and packer (with the
// proxmox plugin installed) is available. CI's packer job sets it.
func TestRenderedTemplatesValidate(t *testing.T) {
	if os.Getenv("PERFECTIMAGE_PACKER_VALIDATE") != "1" {
		t.Skip("set PERFECTIMAGE_PACKER_VALIDATE=1 to run packer validate")
	}
	bin, err := exec.LookPath("packer")
	if err != nil {
		t.Skip("packer not in PATH")
	}
	c := embeddedCatalog(t)
	for _, img := range c.ImageList() {
		t.Run(img.ID, func(t *testing.T) {
			var apps []string
			for _, a := range c.AppList() {
				if a.Supports(img.OSFamily, img.DistroFamily) && len(apps) < 3 {
					apps = append(apps, a.ID)
				}
			}
			apps = append(apps, "docker") // reboot_required on Windows and Linux paths
			req := BuildRequest{ImageID: img.ID, Cluster: "lab", Node: "pve1", TemplateName: "validate", Apps: apps}
			if img.OSFamily == catalog.Windows {
				req.ISOFile = "local:iso/fake.iso"
			}
			im, steps, err := req.Check(c)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			vars := Vars(im, req, false, "validate")
			if im.Seed != nil { // the service adds this after uploading the seed ISO
				vars = append(vars, Var{"seed_iso_file", "local:iso/pi-seed-validate.iso"})
			}
			if err := Render(dir, im, steps, vars); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"init", "."}, {"validate", "."}} {
				cmd := exec.Command(bin, args...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "PKR_VAR_build_password=fake-password",
					"PROXMOX_URL=https://pve.example.invalid:8006/api2/json", "PROXMOX_USERNAME=fake@pve!fake", "PROXMOX_TOKEN=fake")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("packer %s: %v\n%s", args[0], err, out)
				}
			}
		})
	}
}
