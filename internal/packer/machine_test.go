package packer

import (
	"slices"
	"testing"
)

func TestParseMachineLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		ok       bool
		readable []string
		artifact string
	}{
		{"say", "1700000000,,ui,say,==> proxmox-iso.image: Creating VM", true, []string{"==> proxmox-iso.image: Creating VM"}, ""},
		{"message with comma and newline", `1700000000,proxmox-iso.image,ui,message,    a%!(PACKER_COMMA) b\n    c`, true, []string{"    a, b", "    c"}, ""},
		{"error", "1700000000,,ui,error,Build 'x' errored", true, []string{"ERROR: Build 'x' errored"}, ""},
		{"artifact id", "1700000000,proxmox-iso.image,artifact,0,id,9001", true, []string{"==> artifact 0 id: 9001"}, "9001"},
		{"artifact string", "1700000000,proxmox-iso.image,artifact,0,string,A template was created: 9001", true, []string{"==> artifact 0: A template was created: 9001"}, ""},
		{"artifact bookkeeping", "1700000000,proxmox-iso.image,artifact,0,end", true, nil, ""},
		{"version", "1700000000,,version,1.11.2", true, nil, ""},
		{"error-count", "1700000000,,error-count,1", true, []string{"==> errors: 1"}, ""},
		{"not machine readable", "plain stderr text", false, nil, ""},
		{"bad timestamp", "abc,,ui,say,x", false, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, ok := ParseMachineLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ok = %v", ok)
			}
			if !ok {
				return
			}
			if got := ev.Readable(); !slices.Equal(got, tt.readable) {
				t.Fatalf("Readable() = %q, want %q", got, tt.readable)
			}
			id, has := ev.ArtifactID()
			if id != tt.artifact || has != (tt.artifact != "") {
				t.Fatalf("ArtifactID() = %q %v", id, has)
			}
		})
	}
}

func TestHCLStringAndRedactor(t *testing.T) {
	tests := map[string]string{
		`plain`:          `"plain"`,
		`a "q" \ b`:      `"a \"q\" \\ b"`,
		"line\nnext":     `"line\nnext"`,
		"${var.x} %{if}": `"$${var.x} %%{if}"`,
		"$5 100%":        `"$5 100%"`,
	}
	for in, want := range tests {
		if got := hclString(in); got != want {
			t.Errorf("hclString(%q) = %s, want %s", in, got, want)
		}
	}
	r := newRedactor("s3cretPassw0rd", "tok-123456", "")
	if got := r("pw=s3cretPassw0rd token=tok-123456"); got != "pw=<redacted> token=<redacted>" {
		t.Fatalf("redact = %q", got)
	}
	for range 20 {
		p, err := randomPassword(24)
		if err != nil || len(p) != 24 {
			t.Fatalf("password %q %v", p, err)
		}
	}
}
