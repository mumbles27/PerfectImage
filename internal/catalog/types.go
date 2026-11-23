package catalog

import (
	"io/fs"
	"slices"
)

// OSFamily is the guest operating-system family.
type OSFamily string

// OS families.
const (
	Windows OSFamily = "windows"
	Linux   OSFamily = "linux"
)

// Linux distribution families. They decide which package manager methods
// (apt or dnf) apply to an image.
const (
	DistroDebian = "debian" // Debian, Ubuntu (apt)
	DistroRHEL   = "rhel"   // Rocky, Alma, RHEL, Fedora (dnf)
)

// Categories lists the valid app categories.
var Categories = []string{"browser", "dev", "utility", "runtime", "container", "security", "media"}

// Source records where a catalog item was loaded from.
type Source struct {
	// Origin is "embedded" or the override directory the item came from.
	Origin string `json:"origin"`
	// File is the path of the definition file, relative to Origin.
	File string `json:"file"`
}

// Embedded reports whether the item comes from the built-in catalog.
func (s Source) Embedded() bool { return s.Origin == OriginEmbedded }

// String returns "origin/file".
func (s Source) String() string {
	if s.Origin == "" {
		return s.File
	}
	return s.Origin + "/" + s.File
}

// OriginEmbedded is the Source.Origin of built-in catalog items.
const OriginEmbedded = "embedded"

// Image is an image definition: catalog/images/<id>/image.yaml plus the
// Packer HCL, http/ and scripts/ files beside it.
type Image struct {
	ID           string    `yaml:"id" json:"id"`
	Name         string    `yaml:"name" json:"name"`
	Description  string    `yaml:"description" json:"description,omitempty"`
	OSFamily     OSFamily  `yaml:"os_family" json:"os_family"`
	OS           string    `yaml:"os" json:"os"`
	Version      string    `yaml:"version" json:"version"`
	DistroFamily string    `yaml:"distro_family" json:"distro_family,omitempty"`
	Arch         string    `yaml:"arch" json:"arch"`
	ISO          ISO       `yaml:"iso" json:"iso"`
	Firmware     string    `yaml:"firmware" json:"firmware"`
	TPM          bool      `yaml:"tpm" json:"tpm"`
	Resources    Resources `yaml:"resources" json:"resources"`
	Communicator string    `yaml:"communicator" json:"communicator"`
	DefaultApps  []string  `yaml:"default_apps" json:"default_apps,omitempty"`
	Tags         []string  `yaml:"tags" json:"tags,omitempty"`

	Source Source `yaml:"-" json:"source"`
	// Files holds the image directory (image.yaml, *.pkr.hcl, http/, scripts/).
	Files fs.FS `yaml:"-" json:"-"`
}

// ISO describes the install media. Either URL+Checksum (downloaded by
// Proxmox/Packer) or File (an ISO already on Proxmox storage, e.g.
// "local:iso/win2022.iso") is used. Windows images expect a user-supplied
// File plus a VirtioFile for the virtio-win driver ISO.
type ISO struct {
	URL        string `yaml:"url" json:"url,omitempty"`
	Checksum   string `yaml:"checksum" json:"checksum,omitempty"`
	File       string `yaml:"iso_file" json:"iso_file,omitempty"`
	VirtioFile string `yaml:"virtio_iso_file" json:"virtio_iso_file,omitempty"`
}

// Resources are the default VM resources of an image build.
type Resources struct {
	Cores   int    `yaml:"cores" json:"cores"`
	Memory  int    `yaml:"memory" json:"memory"` // MiB
	Disk    string `yaml:"disk" json:"disk"`     // e.g. "32G"
	Storage string `yaml:"storage" json:"storage"`
	Bridge  string `yaml:"bridge" json:"bridge"`
}

// App is an application definition: catalog/apps/<id>.yaml.
type App struct {
	ID             string   `yaml:"id" json:"id"`
	Name           string   `yaml:"name" json:"name"`
	Category       string   `yaml:"category" json:"category"`
	Description    string   `yaml:"description" json:"description,omitempty"`
	Homepage       string   `yaml:"homepage" json:"homepage,omitempty"`
	DependsOn      []string `yaml:"depends_on" json:"depends_on,omitempty"`
	RebootRequired bool     `yaml:"reboot_required" json:"reboot_required"`
	Install        Install  `yaml:"install" json:"install"`

	Source Source `yaml:"-" json:"source"`
}

// Install lists per-OS install methods, tried in order until one installs
// and verifies successfully.
type Install struct {
	Windows []Method `yaml:"windows" json:"windows,omitempty"`
	Linux   []Method `yaml:"linux" json:"linux,omitempty"`
}

// For returns the methods for an OS family.
func (i Install) For(os OSFamily) []Method {
	switch os {
	case Windows:
		return i.Windows
	case Linux:
		return i.Linux
	}
	return nil
}

// Supports reports whether the app has at least one method usable on the
// given OS and distro family.
func (a *App) Supports(os OSFamily, distro string) bool {
	for _, m := range a.Install.For(os) {
		if m.AppliesTo(os, distro) {
			return true
		}
	}
	return false
}

// OSFamilies returns the families the app can be installed on.
func (a *App) OSFamilies() []OSFamily {
	var out []OSFamily
	if len(a.Install.Windows) > 0 {
		out = append(out, Windows)
	}
	if len(a.Install.Linux) > 0 {
		out = append(out, Linux)
	}
	return out
}

// Method is one install method. Exactly one of the method fields must be
// set; Verify is a command that exits 0 when the app is installed.
type Method struct {
	// Windows methods.
	Winget     *Winget    `yaml:"winget,omitempty" json:"winget,omitempty"`
	Choco      *Choco     `yaml:"choco,omitempty" json:"choco,omitempty"`
	MSI        *Installer `yaml:"msi,omitempty" json:"msi,omitempty"`
	EXE        *Installer `yaml:"exe,omitempty" json:"exe,omitempty"`
	PowerShell *Script    `yaml:"powershell,omitempty" json:"powershell,omitempty"`
	// Linux methods.
	Apt     *Package `yaml:"apt,omitempty" json:"apt,omitempty"`
	Dnf     *Package `yaml:"dnf,omitempty" json:"dnf,omitempty"`
	Snap    *Snap    `yaml:"snap,omitempty" json:"snap,omitempty"`
	Flatpak *Flatpak `yaml:"flatpak,omitempty" json:"flatpak,omitempty"`
	Tarball *Tarball `yaml:"tarball,omitempty" json:"tarball,omitempty"`
	Shell   *Script  `yaml:"shell,omitempty" json:"shell,omitempty"`

	// Distros optionally restricts a Linux method to distro families
	// ("debian", "rhel"). apt and dnf are implicitly restricted.
	Distros []string `yaml:"distros,omitempty" json:"distros,omitempty"`
	// Verify is a bash (Linux) or PowerShell (Windows) command that exits 0
	// when the app is installed.
	Verify string `yaml:"verify" json:"verify"`
}

// Kind returns the method type name ("winget", "apt", ...), or "" when no
// method field is set, or "multiple" when more than one is.
func (m Method) Kind() string {
	kinds := m.kinds()
	switch len(kinds) {
	case 0:
		return ""
	case 1:
		return kinds[0]
	}
	return "multiple"
}

func (m Method) kinds() []string {
	var k []string
	add := func(set bool, name string) {
		if set {
			k = append(k, name)
		}
	}
	add(m.Winget != nil, "winget")
	add(m.Choco != nil, "choco")
	add(m.MSI != nil, "msi")
	add(m.EXE != nil, "exe")
	add(m.PowerShell != nil, "powershell")
	add(m.Apt != nil, "apt")
	add(m.Dnf != nil, "dnf")
	add(m.Snap != nil, "snap")
	add(m.Flatpak != nil, "flatpak")
	add(m.Tarball != nil, "tarball")
	add(m.Shell != nil, "shell")
	return k
}

// WindowsKinds and LinuxKinds list the method types valid per OS family.
var (
	WindowsKinds = []string{"winget", "choco", "msi", "exe", "powershell"}
	LinuxKinds   = []string{"apt", "dnf", "snap", "flatpak", "tarball", "shell"}
)

// AppliesTo reports whether the method can be used on os/distro. An empty
// distro matches every Linux method.
func (m Method) AppliesTo(os OSFamily, distro string) bool {
	kind := m.Kind()
	switch os {
	case Windows:
		return slices.Contains(WindowsKinds, kind)
	case Linux:
		if !slices.Contains(LinuxKinds, kind) {
			return false
		}
		if distro == "" {
			return true
		}
		switch kind {
		case "apt":
			return distro == DistroDebian
		case "dnf":
			return distro == DistroRHEL
		}
		return len(m.Distros) == 0 || slices.Contains(m.Distros, distro)
	}
	return false
}

// Winget installs a package with winget.
type Winget struct {
	ID      string `yaml:"id" json:"id"`
	Source  string `yaml:"source,omitempty" json:"source,omitempty"` // default "winget"
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	Scope   string `yaml:"scope,omitempty" json:"scope,omitempty"` // machine (default) | user
}

// Choco installs a Chocolatey package (Chocolatey is bootstrapped if missing).
type Choco struct {
	Package string `yaml:"package" json:"package"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
}

// Installer downloads an MSI or EXE, verifies its SHA-256 and runs it
// silently.
type Installer struct {
	URL    string `yaml:"url" json:"url"`
	SHA256 string `yaml:"sha256" json:"sha256"`
	// Args are the silent-install arguments. MSI defaults to "/qn /norestart".
	Args string `yaml:"args,omitempty" json:"args,omitempty"`
}

// Script is an inline script (PowerShell on Windows, bash on Linux).
type Script struct {
	Script string `yaml:"script" json:"script"`
}

// Package installs distro packages with apt or dnf, optionally adding a
// vendor repository first.
type Package struct {
	Packages []string `yaml:"packages" json:"packages"`
	Repo     *Repo    `yaml:"repo,omitempty" json:"repo,omitempty"`
}

// Repo is a vendor package repository.
//
// For apt the source line is
// "deb [signed-by=/etc/apt/keyrings/<name>.gpg] <url> <suite> <components>";
// "{codename}" in Suite is replaced by the distro codename. For dnf, URL is
// the baseurl ("$releasever"/"$basearch" are expanded by dnf).
type Repo struct {
	Name       string `yaml:"name" json:"name"`
	URL        string `yaml:"url" json:"url"`
	KeyURL     string `yaml:"key_url" json:"key_url"`
	Suite      string `yaml:"suite,omitempty" json:"suite,omitempty"`
	Components string `yaml:"components,omitempty" json:"components,omitempty"`
}

// Snap installs a snap (snapd is installed if missing).
type Snap struct {
	Name    string `yaml:"name" json:"name"`
	Classic bool   `yaml:"classic,omitempty" json:"classic,omitempty"`
	Channel string `yaml:"channel,omitempty" json:"channel,omitempty"`
}

// Flatpak installs a flatpak application (flatpak is installed if missing).
type Flatpak struct {
	ID     string `yaml:"id" json:"id"`
	Remote string `yaml:"remote,omitempty" json:"remote,omitempty"` // default flathub
}

// Tarball downloads an archive, verifies its SHA-256 and unpacks it.
type Tarball struct {
	URL             string `yaml:"url" json:"url"`
	SHA256          string `yaml:"sha256" json:"sha256"`
	Dest            string `yaml:"dest" json:"dest"` // absolute directory, e.g. /usr/local/go
	StripComponents int    `yaml:"strip_components,omitempty" json:"strip_components,omitempty"`
	// Bin lists paths (relative to Dest) to symlink into /usr/local/bin.
	Bin []string `yaml:"bin,omitempty" json:"bin,omitempty"`
}

// Bundle is a named group of apps: catalog/bundles/<id>.yaml.
type Bundle struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description,omitempty"`
	Apps        []string `yaml:"apps" json:"apps"`

	Source Source `yaml:"-" json:"source"`
}

// InstallStep is one resolved app install, ready to run on a guest. The
// deploy package consumes these through an adapter; the packer package turns
// them into provisioners.
type InstallStep struct {
	// AppID and Name identify the app.
	AppID string `json:"app_id"`
	Name  string `json:"name"`
	// Shell is "bash" or "powershell".
	Shell string `json:"shell"`
	// Script installs the app, trying each method in order. It exits 0 on
	// success (including "already installed") and non-zero on failure.
	Script string `json:"script"`
	// VerifyScript exits 0 when the app is installed.
	VerifyScript   string `json:"verify_script"`
	RebootRequired bool   `json:"reboot_required"`
}

// Shells.
const (
	ShellBash       = "bash"
	ShellPowerShell = "powershell"
)
