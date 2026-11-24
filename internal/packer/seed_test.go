package packer

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	diskfs "github.com/diskfs/go-diskfs"

	"github.com/mumbles27/PerfectImage/internal/catalog"
)

func embeddedImage(t *testing.T, id string) *catalog.Image {
	t.Helper()
	s := catalog.NewStore(catalog.EmbeddedFS(), nil, nil)
	if _, err := s.Reload(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	c := s.Catalog()
	for _, p := range c.Problems {
		t.Errorf("catalog problem: %s", p)
	}
	img, ok := c.Images[id]
	if !ok {
		t.Fatalf("image %s missing", id)
	}
	return img
}

func TestRenderSeed(t *testing.T) {
	const pw = `Abc123"quote`
	tests := []struct {
		image, label string
		want         map[string][]string
	}{
		{"ubuntu-24.04", "cidata", map[string][]string{
			"user-data": {"#cloud-config", "autoinstall:", "name: packer", `plain_text_passwd: "Abc123\"quote"`},
			"meta-data": nil,
		}},
		{"rocky-9", "OEMDRV", map[string][]string{
			"ks.cfg": {"user --name=packer --password=" + pw, "packer ALL=(ALL) NOPASSWD:ALL"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			img := embeddedImage(t, tt.image)
			if img.Seed == nil || img.Seed.Label != tt.label {
				t.Fatalf("seed = %+v", img.Seed)
			}
			files, err := RenderSeed(img, SeedData{Username: BuildUsername, Password: pw})
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != len(tt.want) {
				t.Fatalf("files = %d, want %d", len(files), len(tt.want))
			}
			for name, subs := range tt.want {
				body, ok := files[name]
				if !ok {
					t.Fatalf("missing %s", name)
				}
				for _, s := range subs {
					if !strings.Contains(string(body), s) {
						t.Errorf("%s lacks %q:\n%s", name, s, body)
					}
				}
				if strings.Contains(string(body), "{{") || strings.Contains(string(body), "${") {
					t.Errorf("%s has unrendered template syntax", name)
				}
			}
		})
	}
}

func TestSeedISO(t *testing.T) {
	files := map[string][]byte{
		"user-data": []byte("#cloud-config\nautoinstall:\n  version: 1\n"),
		"meta-data": nil,
		"ks.cfg":    bytes.Repeat([]byte("x"), 5000),
	}
	iso, err := SeedISO("cidata", files)
	if err != nil {
		t.Fatal(err)
	}
	// Primary Volume Descriptor at sector 16: type 1, "CD001", volume id at 40.
	if len(iso) < 34816 || iso[32768] != 1 || string(iso[32769:32774]) != "CD001" {
		t.Fatal("no ISO 9660 primary volume descriptor")
	}
	if vol := strings.TrimSpace(string(iso[32768+40 : 32768+72])); !strings.EqualFold(vol, "cidata") {
		t.Fatalf("volume id = %q", vol)
	}
	// Rock Ridge NM entries keep the original (lower-case, hyphenated) names.
	for name := range files {
		if !bytes.Contains(iso, []byte(name)) {
			t.Errorf("file name %q not present (Rock Ridge/Joliet missing?)", name)
		}
	}
	// Read it back and compare content.
	p := filepath.Join(t.TempDir(), "seed.iso")
	if err := os.WriteFile(p, iso, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := diskfs.Open(p, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.LogicalBlocksize = 2048
	fsys, err := d.GetFilesystem(0)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		f, err := fsys.OpenFile("/"+name, os.O_RDONLY)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		got, _ := io.ReadAll(f)
		_ = f.Close()
		if !bytes.Equal(got, want) {
			t.Errorf("%s: %d bytes, want %d", name, len(got), len(want))
		}
	}
}
