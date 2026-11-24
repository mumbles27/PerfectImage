package catalog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// String formats a problem as "file:line: message".
func (p Problem) String() string {
	if p.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Message)
	}
	return fmt.Sprintf("%s: %s", p.File, p.Message)
}

// AppsMarker is the line in an image's build.pkr.hcl that the packer
// renderer replaces with the generated app provisioners.
const AppsMarker = "# @perfectimage:apps"

// Value syntax. Everything that is interpolated into generated scripts is
// restricted to a safe alphabet (and quoted on top of that).
var (
	idRE        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	pkgRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:@-]{0,127}$`)
	wingetIDRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	versionRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$`)
	nameRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	wordsRE     = regexp.MustCompile(`^[A-Za-z0-9{}._/-]+( [A-Za-z0-9{}._/-]+)*$`)
	channelRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]{0,63}$`)
	sha256RE    = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	checksumRE  = regexp.MustCompile(`^((sha256|sha512|sha1|md5):[a-fA-F0-9]+|file:https://\S+|none)$`)
	isoFileRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*:iso/[A-Za-z0-9._+-]+\.iso$`)
	diskRE      = regexp.MustCompile(`^[1-9][0-9]*[GMT]$`)
	pveNameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	tagRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.+-]{0,63}$`)
	destRE      = regexp.MustCompile(`^/(opt|usr/local)/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	relPathRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	installArgs = regexp.MustCompile("^[^\r\n`$;|&<>]*$")
)

type checker struct {
	file  string
	root  *yaml.Node
	probs []Problem
}

func (c *checker) at(keys []any, format string, a ...any) {
	c.probs = append(c.probs, Problem{File: c.file, Line: lineOf(c.root, keys...), Message: fmt.Sprintf(format, a...)})
}

func k(keys ...any) []any { return keys }

func (c *checker) required(keys []any, field, v string) bool {
	if strings.TrimSpace(v) == "" {
		c.at(keys, "%s is required", field)
		return false
	}
	return true
}

func (c *checker) match(keys []any, field, v string, re *regexp.Regexp) {
	if v != "" && !re.MatchString(v) {
		c.at(keys, "%s %q has an invalid format", field, v)
	}
}

func (c *checker) httpsURL(keys []any, field, v string) {
	if !c.required(keys, field, v) {
		return
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || strings.ContainsAny(v, " '\"`$\\") {
		c.at(keys, "%s must be an https URL without quotes or spaces", field)
	}
}

func validateApp(a *App, root *yaml.Node, file string) []Problem {
	c := &checker{file: file, root: root}
	if c.required(k("id"), "id", a.ID) {
		c.match(k("id"), "id", a.ID, idRE)
	}
	c.required(k("name"), "name", a.Name)
	if !slices.Contains(Categories, a.Category) {
		c.at(k("category"), "category %q must be one of %s", a.Category, strings.Join(Categories, ", "))
	}
	if a.Homepage != "" {
		c.httpsURL(k("homepage"), "homepage", a.Homepage)
	}
	for i, d := range a.DependsOn {
		c.match(k("depends_on", i), "depends_on entry", d, idRE)
		if d == a.ID {
			c.at(k("depends_on", i), "app cannot depend on itself")
		}
	}
	if len(a.Install.Windows) == 0 && len(a.Install.Linux) == 0 {
		c.at(k("install"), "install must define at least one windows or linux method")
	}
	for i, m := range a.Install.Windows {
		c.method(Windows, m, k("install", "windows", i))
	}
	for i, m := range a.Install.Linux {
		c.method(Linux, m, k("install", "linux", i))
	}
	return c.probs
}

func (c *checker) method(os OSFamily, m Method, at []any) {
	sub := func(more ...any) []any { return append(slices.Clone(at), more...) }
	kind := m.Kind()
	valid := WindowsKinds
	if os == Linux {
		valid = LinuxKinds
	}
	switch {
	case kind == "":
		c.at(at, "method must set one of %s", strings.Join(valid, ", "))
		return
	case kind == "multiple":
		c.at(at, "method sets more than one of %s; use one list entry per method", strings.Join(m.kinds(), ", "))
		return
	case !slices.Contains(valid, kind):
		c.at(at, "%s is not a %s install method (use one of %s)", kind, os, strings.Join(valid, ", "))
		return
	}
	c.required(sub("verify"), "verify", m.Verify)
	if strings.ContainsAny(m.Verify, "\x00") {
		c.at(sub("verify"), "verify contains a NUL byte")
	}
	for i, d := range m.Distros {
		if d != DistroDebian && d != DistroRHEL {
			c.at(sub("distros", i), "distro %q must be %s or %s", d, DistroDebian, DistroRHEL)
		}
	}
	if len(m.Distros) > 0 && (os == Windows || kind == "apt" || kind == "dnf") {
		c.at(sub("distros"), "distros only applies to snap, flatpak, tarball and shell methods")
	}
	switch kind {
	case "winget":
		if c.required(sub("winget", "id"), "winget.id", m.Winget.ID) {
			c.match(sub("winget", "id"), "winget.id", m.Winget.ID, wingetIDRE)
		}
		if s := m.Winget.Source; s != "" && s != "winget" && s != "msstore" {
			c.at(sub("winget", "source"), "winget.source must be winget or msstore")
		}
		if s := m.Winget.Scope; s != "" && s != "machine" && s != "user" {
			c.at(sub("winget", "scope"), "winget.scope must be machine or user")
		}
		c.match(sub("winget", "version"), "winget.version", m.Winget.Version, versionRE)
	case "choco":
		if c.required(sub("choco", "package"), "choco.package", m.Choco.Package) {
			c.match(sub("choco", "package"), "choco.package", m.Choco.Package, wingetIDRE)
		}
		c.match(sub("choco", "version"), "choco.version", m.Choco.Version, versionRE)
	case "msi", "exe":
		inst := m.MSI
		if kind == "exe" {
			inst = m.EXE
		}
		c.httpsURL(sub(kind, "url"), kind+".url", inst.URL)
		if c.required(sub(kind, "sha256"), kind+".sha256", inst.SHA256) {
			c.match(sub(kind, "sha256"), kind+".sha256", inst.SHA256, sha256RE)
		}
		c.match(sub(kind, "args"), kind+".args", inst.Args, installArgs)
	case "powershell":
		c.required(sub("powershell", "script"), "powershell.script", m.PowerShell.Script)
	case "shell":
		c.required(sub("shell", "script"), "shell.script", m.Shell.Script)
	case "apt", "dnf":
		p := m.Apt
		if kind == "dnf" {
			p = m.Dnf
		}
		if len(p.Packages) == 0 {
			c.at(sub(kind, "packages"), "%s.packages must list at least one package", kind)
		}
		for i, n := range p.Packages {
			c.match(sub(kind, "packages", i), "package", n, pkgRE)
		}
		if r := p.Repo; r != nil {
			rk := sub(kind, "repo")
			if c.required(append(slices.Clone(rk), "name"), "repo.name", r.Name) {
				c.match(append(slices.Clone(rk), "name"), "repo.name", r.Name, nameRE)
			}
			u := r.URL
			if kind == "dnf" {
				// dnf expands these; the .repo file is written verbatim.
				u = strings.NewReplacer("$releasever", "9", "$basearch", "x86_64").Replace(u)
			}
			c.httpsURL(append(slices.Clone(rk), "url"), "repo.url", u)
			c.httpsURL(append(slices.Clone(rk), "key_url"), "repo.key_url", r.KeyURL)
			if kind == "apt" {
				if c.required(append(slices.Clone(rk), "suite"), "repo.suite", r.Suite) {
					c.match(append(slices.Clone(rk), "suite"), "repo.suite", r.Suite, wordsRE)
				}
				c.match(append(slices.Clone(rk), "components"), "repo.components", r.Components, wordsRE)
			} else if r.Suite != "" || r.Components != "" {
				c.at(rk, "repo.suite and repo.components only apply to apt")
			}
		}
	case "snap":
		if c.required(sub("snap", "name"), "snap.name", m.Snap.Name) {
			c.match(sub("snap", "name"), "snap.name", m.Snap.Name, nameRE)
		}
		c.match(sub("snap", "channel"), "snap.channel", m.Snap.Channel, channelRE)
	case "flatpak":
		if c.required(sub("flatpak", "id"), "flatpak.id", m.Flatpak.ID) {
			c.match(sub("flatpak", "id"), "flatpak.id", m.Flatpak.ID, wingetIDRE)
		}
		c.match(sub("flatpak", "remote"), "flatpak.remote", m.Flatpak.Remote, nameRE)
	case "tarball":
		t := m.Tarball
		c.httpsURL(sub("tarball", "url"), "tarball.url", t.URL)
		if c.required(sub("tarball", "sha256"), "tarball.sha256", t.SHA256) {
			c.match(sub("tarball", "sha256"), "tarball.sha256", t.SHA256, sha256RE)
		}
		if c.required(sub("tarball", "dest"), "tarball.dest", t.Dest) && !destRE.MatchString(t.Dest) {
			c.at(sub("tarball", "dest"), "tarball.dest must be a directory below /opt or /usr/local")
		}
		if t.StripComponents < 0 || t.StripComponents > 5 {
			c.at(sub("tarball", "strip_components"), "tarball.strip_components must be between 0 and 5")
		}
		for i, b := range t.Bin {
			if !relPathRE.MatchString(b) || slices.Contains(strings.Split(b, "/"), "..") {
				c.at(sub("tarball", "bin", i), "tarball.bin entries must be relative paths inside dest")
			}
		}
	}
}

func validateBundle(b *Bundle, root *yaml.Node, file string) []Problem {
	c := &checker{file: file, root: root}
	if c.required(k("id"), "id", b.ID) {
		c.match(k("id"), "id", b.ID, idRE)
	}
	c.required(k("name"), "name", b.Name)
	if len(b.Apps) == 0 {
		c.at(k("apps"), "apps must list at least one app")
	}
	seen := map[string]bool{}
	for i, a := range b.Apps {
		c.match(k("apps", i), "app id", a, idRE)
		if seen[a] {
			c.at(k("apps", i), "app %q is listed twice", a)
		}
		seen[a] = true
	}
	return c.probs
}

func validateImage(img *Image, root *yaml.Node, file string) []Problem {
	c := &checker{file: file, root: root}
	if c.required(k("id"), "id", img.ID) {
		c.match(k("id"), "id", img.ID, idRE)
	}
	c.required(k("name"), "name", img.Name)
	c.required(k("os"), "os", img.OS)
	c.required(k("version"), "version", img.Version)
	switch img.OSFamily {
	case Linux:
		if img.DistroFamily != DistroDebian && img.DistroFamily != DistroRHEL {
			c.at(k("distro_family"), "distro_family must be %s or %s for linux images", DistroDebian, DistroRHEL)
		}
		if img.Communicator != "ssh" {
			c.at(k("communicator"), "linux images must use the ssh communicator")
		}
		if img.ISO.VirtioFile != "" {
			c.at(k("iso", "virtio_iso_file"), "virtio_iso_file only applies to windows images")
		}
	case Windows:
		if img.DistroFamily != "" {
			c.at(k("distro_family"), "distro_family only applies to linux images")
		}
		if img.Communicator != "winrm" {
			c.at(k("communicator"), "windows images must use the winrm communicator")
		}
		if c.required(k("iso", "virtio_iso_file"), "iso.virtio_iso_file", img.ISO.VirtioFile) {
			c.match(k("iso", "virtio_iso_file"), "iso.virtio_iso_file", img.ISO.VirtioFile, isoFileRE)
		}
	default:
		c.at(k("os_family"), "os_family must be windows or linux")
	}
	if img.Arch != "amd64" && img.Arch != "arm64" {
		c.at(k("arch"), "arch must be amd64 or arm64")
	}
	switch {
	case img.ISO.File != "":
		c.match(k("iso", "iso_file"), "iso.iso_file", img.ISO.File, isoFileRE)
		if img.ISO.URL != "" {
			c.at(k("iso", "url"), "set either iso.url or iso.iso_file, not both")
		}
	case img.ISO.URL != "":
		c.httpsURL(k("iso", "url"), "iso.url", img.ISO.URL)
		if c.required(k("iso", "checksum"), "iso.checksum", img.ISO.Checksum) {
			c.match(k("iso", "checksum"), "iso.checksum", img.ISO.Checksum, checksumRE)
		}
	default:
		c.at(k("iso"), "iso needs url + checksum or iso_file (e.g. local:iso/install.iso)")
	}
	if img.Firmware != "bios" && img.Firmware != "uefi" {
		c.at(k("firmware"), "firmware must be bios or uefi")
	}
	if img.TPM && img.Firmware != "uefi" {
		c.at(k("tpm"), "tpm requires uefi firmware")
	}
	r := img.Resources
	if r.Cores < 1 || r.Cores > 256 {
		c.at(k("resources", "cores"), "resources.cores must be between 1 and 256")
	}
	if r.Memory < 512 {
		c.at(k("resources", "memory"), "resources.memory must be at least 512 (MiB)")
	}
	if c.required(k("resources", "disk"), "resources.disk", r.Disk) {
		c.match(k("resources", "disk"), "resources.disk", r.Disk, diskRE)
	}
	if c.required(k("resources", "storage"), "resources.storage", r.Storage) {
		c.match(k("resources", "storage"), "resources.storage", r.Storage, pveNameRE)
	}
	if c.required(k("resources", "bridge"), "resources.bridge", r.Bridge) {
		c.match(k("resources", "bridge"), "resources.bridge", r.Bridge, pveNameRE)
	}
	for i, a := range img.DefaultApps {
		c.match(k("default_apps", i), "default app", a, idRE)
	}
	for i, t := range img.Tags {
		c.match(k("tags", i), "tag", t, tagRE)
	}
	if s := img.Seed; s != nil {
		if c.required(k("seed", "label"), "seed.label", s.Label) {
			c.match(k("seed", "label"), "seed.label", s.Label, seedLabelRE)
		}
		if len(s.Files) == 0 {
			c.at(k("seed", "files"), "seed.files must list at least one file")
		}
		seen := map[string]bool{}
		for i, f := range s.Files {
			if c.required(k("seed", "files", i, "name"), "seed file name", f.Name) {
				c.match(k("seed", "files", i, "name"), "seed file name", f.Name, seedNameRE)
			}
			if seen[f.Name] {
				c.at(k("seed", "files", i, "name"), "seed file %q is listed twice", f.Name)
			}
			seen[f.Name] = true
			if f.Template != "" && (!relPathRE.MatchString(f.Template) || slices.Contains(strings.Split(f.Template, "/"), "..")) {
				c.at(k("seed", "files", i, "template"), "seed template must be a relative path inside the image directory")
			}
		}
	}
	return c.probs
}

var (
	seedLabelRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
	seedNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// SeedFuncs are the functions available to seed templates.
var SeedFuncs = template.FuncMap{
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
}

// validateSeedFiles checks that seed templates exist and parse.
func validateSeedFiles(img *Image, fsys fs.FS, dir string) []Problem {
	if img.Seed == nil {
		return nil
	}
	var probs []Problem
	for _, f := range img.Seed.Files {
		if f.Template == "" {
			continue
		}
		file := path.Join(dir, f.Template)
		b, err := fs.ReadFile(fsys, f.Template)
		if err != nil {
			probs = append(probs, Problem{File: file, Message: "seed template not found"})
			continue
		}
		if _, err := template.New(f.Name).Funcs(SeedFuncs).Parse(string(b)); err != nil {
			probs = append(probs, Problem{File: file, Message: "seed template: " + err.Error()})
		}
	}
	return probs
}

// validateImageFiles checks the Packer files of an image directory.
func validateImageFiles(fsys fs.FS, dir string) []Problem {
	var probs []Problem
	add := func(file string, line int, format string, a ...any) {
		probs = append(probs, Problem{File: file, Line: line, Message: fmt.Sprintf(format, a...)})
	}
	hcl, _ := fs.Glob(fsys, "*.pkr.hcl")
	if len(hcl) == 0 {
		add(dir, 0, "image has no *.pkr.hcl files")
	}
	b, err := fs.ReadFile(fsys, "build.pkr.hcl")
	bf := path.Join(dir, "build.pkr.hcl")
	if err != nil {
		add(bf, 0, "missing build.pkr.hcl (the build block with the %q line)", AppsMarker)
		return probs
	}
	var markers []int
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		if strings.TrimSpace(sc.Text()) == AppsMarker {
			markers = append(markers, n)
		}
	}
	switch len(markers) {
	case 0:
		add(bf, 0, "build block must contain the line %q where app provisioners are inserted", AppsMarker)
	case 1:
	default:
		add(bf, markers[1], "%q must appear exactly once", AppsMarker)
	}
	if !bytes.Contains(b, []byte(`source.proxmox-iso.`)) {
		add(bf, 0, "build must use a proxmox-iso source")
	}
	return probs
}

// crossValidate checks references between items: dependencies (existence and
// cycles), bundle members, image default apps and id clashes.
func crossValidate(c *Catalog, nodes map[string]parsed) []Problem {
	var probs []Problem
	at := func(key string, keys []any, format string, a ...any) {
		p := nodes[key]
		probs = append(probs, Problem{File: p.file, Line: lineOf(p.root, keys...), Message: fmt.Sprintf(format, a...)})
	}
	for _, a := range c.AppList() {
		for i, d := range a.DependsOn {
			dep, ok := c.Apps[d]
			if !ok {
				at("app:"+a.ID, k("depends_on", i), "unknown dependency %q", d)
				continue
			}
			for _, os := range a.OSFamilies() {
				if !slices.Contains(dep.OSFamilies(), os) {
					at("app:"+a.ID, k("depends_on", i), "dependency %q has no %s install methods", d, os)
				}
			}
		}
	}
	for _, cyc := range findCycles(c) {
		at("app:"+cyc[0], k("depends_on"), "dependency cycle: %s", strings.Join(cyc, " -> "))
	}
	for _, b := range c.BundleList() {
		if _, clash := c.Apps[b.ID]; clash {
			at("bundle:"+b.ID, k("id"), "bundle id %q clashes with an app id", b.ID)
		}
		for i, id := range b.Apps {
			if _, ok := c.Apps[id]; !ok {
				at("bundle:"+b.ID, k("apps", i), "unknown app %q", id)
			}
		}
	}
	for _, img := range c.ImageList() {
		for i, id := range img.DefaultApps {
			a, ok := c.Apps[id]
			switch {
			case !ok:
				at("image:"+img.ID, k("default_apps", i), "unknown app %q", id)
			case !a.Supports(img.OSFamily, img.DistroFamily):
				at("image:"+img.ID, k("default_apps", i), "app %q has no install method for %s/%s", id, img.OSFamily, img.DistroFamily)
			}
		}
	}
	return probs
}

// findCycles returns each dependency cycle once, as a path that starts and
// ends with the same app id.
func findCycles(c *Catalog) [][]string {
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var stack []string
	var cycles [][]string
	var visit func(id string)
	visit = func(id string) {
		color[id] = grey
		stack = append(stack, id)
		a := c.Apps[id]
		for _, d := range a.DependsOn {
			if _, ok := c.Apps[d]; !ok {
				continue
			}
			switch color[d] {
			case white:
				visit(d)
			case grey:
				i := slices.Index(stack, d)
				cyc := append(slices.Clone(stack[i:]), d)
				cycles = append(cycles, cyc)
			}
		}
		stack = stack[:len(stack)-1]
		color[id] = black
	}
	for _, a := range c.AppList() {
		if color[a.ID] == white {
			visit(a.ID)
		}
	}
	return cycles
}
