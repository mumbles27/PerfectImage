package deploy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/secrets"
)

// JobType is the job type registered by this package.
const JobType = "deploy.vm"

// IP modes.
const (
	IPDHCP   = "dhcp"
	IPStatic = "static"
)

// Request is the deploy.vm job payload. Secret fields hold sealed values
// (see SealSecret) and are never logged.
type Request struct {
	// RequestID is random and binds sealed fields to this request.
	RequestID string `json:"request_id"`

	Cluster      string `json:"cluster"`
	TemplateNode string `json:"template_node"`
	TemplateVMID int    `json:"template_vmid"`
	TemplateName string `json:"template_name,omitempty"`

	// Node is the target node ("" = template node).
	Node string `json:"node,omitempty"`
	// Storage for a full clone's disks ("" = same as template).
	Storage string `json:"storage,omitempty"`
	Pool    string `json:"pool,omitempty"`
	Name    string `json:"name"`
	// VMID 0 means next free ID.
	VMID        int  `json:"vmid,omitempty"`
	LinkedClone bool `json:"linked_clone,omitempty"`

	Cores    int `json:"cores,omitempty"`
	MemoryMB int `json:"memory_mb,omitempty"`
	// DiskGB grows the boot disk to this size (0 = keep template size).
	DiskGB int `json:"disk_gb,omitempty"`

	Bridge string `json:"bridge,omitempty"`
	VLAN   int    `json:"vlan,omitempty"`

	// Network: IPMode is dhcp or static; IPCIDR like 10.0.0.5/24.
	IPMode       string   `json:"ip_mode"`
	IPCIDR       string   `json:"ip_cidr,omitempty"`
	Gateway      string   `json:"gateway,omitempty"`
	DNSServers   []string `json:"dns_servers,omitempty"`
	SearchDomain string   `json:"search_domain,omitempty"`

	// OS is "linux" or "windows" (from the template's ostype).
	OS      string         `json:"os"`
	Linux   LinuxOptions   `json:"linux,omitempty"`
	Windows WindowsOptions `json:"windows,omitempty"`

	Apps             []string `json:"apps,omitempty"`
	CleanupOnFailure bool     `json:"cleanup_on_failure"`
}

// LinuxOptions are cloud-init settings.
type LinuxOptions struct {
	User    string   `json:"user,omitempty"`
	SSHKeys []string `json:"ssh_keys,omitempty"`
}

// WindowsOptions are applied through the guest agent after first boot.
type WindowsOptions struct {
	Hostname string `json:"hostname,omitempty"`
	// AdminPassword is sealed (SealSecret field "admin_password").
	AdminPassword string `json:"admin_password,omitempty"`
	Domain        string `json:"domain,omitempty"`
	DomainUser    string `json:"domain_user,omitempty"`
	// DomainPassword is sealed (SealSecret field "domain_password").
	DomainPassword string `json:"domain_password,omitempty"`
	DomainOU       string `json:"domain_ou,omitempty"`
}

// NewRequestID returns a random request ID.
func NewRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func secretAAD(requestID, field string) string { return "deploy.vm:" + requestID + ":" + field }

// SealSecret seals a request secret field.
func SealSecret(s secrets.Sealer, requestID, field, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return secrets.EncryptString(s, value, secretAAD(requestID, field))
}

// OpenSecret unseals a request secret field.
func OpenSecret(s secrets.Sealer, requestID, field, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	return secrets.DecryptString(s, sealed, secretAAD(requestID, field))
}

var (
	vmNameRe      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	pveIDRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	netbiosRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
	domainRe      = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	linuxUserRe   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	domainUserRe  = regexp.MustCompile(`^[A-Za-z0-9._\-\\@]{1,104}$`)
	appIDRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reservedNames = map[string]bool{"root": true}
)

// Validate checks the request. Sealed fields are only checked for presence.
func (r *Request) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if r.RequestID == "" {
		add("request id missing")
	}
	if r.Cluster == "" {
		add("choose a cluster")
	}
	if r.TemplateVMID <= 0 || r.TemplateNode == "" {
		add("choose a template")
	}
	for name, v := range map[string]string{"template node": r.TemplateNode, "node": r.Node, "storage": r.Storage,
		"pool": r.Pool, "bridge": r.Bridge} {
		if v != "" && !pveIDRe.MatchString(v) {
			add("invalid %s %q", name, v)
		}
	}
	if !vmNameRe.MatchString(r.Name) || len(r.Name) > 253 {
		add("name must be a valid DNS name (letters, digits, '-', '.')")
	}
	if r.VMID != 0 && (r.VMID < 100 || r.VMID > 999999999) {
		add("VMID must be between 100 and 999999999 (or empty for the next free ID)")
	}
	if r.Cores < 0 || r.Cores > 512 {
		add("cores must be between 1 and 512")
	}
	if r.MemoryMB != 0 && (r.MemoryMB < 16 || r.MemoryMB > 16<<20) {
		add("memory must be between 16 MiB and 16 TiB")
	}
	if r.DiskGB < 0 || r.DiskGB > 65536 {
		add("disk size must be between 1 and 65536 GiB")
	}
	if r.VLAN < 0 || r.VLAN > 4094 {
		add("VLAN tag must be between 1 and 4094")
	}
	if r.VLAN != 0 && r.Bridge == "" {
		add("a VLAN tag needs a bridge")
	}
	switch r.IPMode {
	case IPDHCP, "":
		if r.IPCIDR != "" || r.Gateway != "" {
			add("IP address and gateway are only used with a static IP")
		}
	case IPStatic:
		pfx, err := netip.ParsePrefix(r.IPCIDR)
		if err != nil || !pfx.Addr().Is4() && !pfx.Addr().Is6() {
			add("static IP must be in CIDR form, e.g. 10.0.0.5/24")
		}
		if r.Gateway != "" {
			gw, err := netip.ParseAddr(r.Gateway)
			if err != nil {
				add("invalid gateway %q", r.Gateway)
			} else if pfx.IsValid() && !pfx.Masked().Contains(gw) {
				add("gateway %s is outside %s", gw, pfx.Masked())
			}
		}
	default:
		add("IP mode must be dhcp or static")
	}
	for _, d := range r.DNSServers {
		if _, err := netip.ParseAddr(d); err != nil {
			add("invalid DNS server %q", d)
		}
	}
	if r.SearchDomain != "" && !domainRe.MatchString(r.SearchDomain) {
		add("invalid search domain %q", r.SearchDomain)
	}
	switch r.OS {
	case OSLinux:
		if r.Linux.User != "" && (!linuxUserRe.MatchString(r.Linux.User) || reservedNames[r.Linux.User]) {
			add("cloud-init user must be a lower-case Linux user name (not root)")
		}
		for _, k := range r.Linux.SSHKeys {
			if err := checkSSHKey(k); err != nil {
				add("invalid SSH public key %q", truncate(k, 40))
			}
		}
		if len(r.Linux.SSHKeys) > 0 && r.Linux.User == "" {
			add("SSH keys need a cloud-init user")
		}
	case OSWindows:
		w := r.Windows
		if w.Hostname != "" && !netbiosRe.MatchString(w.Hostname) {
			add("Windows hostname must be 1-15 letters, digits or '-'")
		}
		if w.Domain != "" {
			if !domainRe.MatchString(w.Domain) {
				add("invalid domain %q", w.Domain)
			}
			if !domainUserRe.MatchString(w.DomainUser) {
				add("domain join needs a user (e.g. CORP\\joiner or joiner@corp.example)")
			}
			if w.DomainPassword == "" {
				add("domain join needs a password")
			}
			if strings.ContainsAny(w.DomainOU, "\r\n") || len(w.DomainOU) > 512 {
				add("invalid OU path")
			}
		} else if w.DomainUser != "" || w.DomainPassword != "" || w.DomainOU != "" {
			add("domain user, password and OU need a domain")
		}
	default:
		add("unknown OS %q", r.OS)
	}
	for _, a := range r.Apps {
		if !appIDRe.MatchString(a) {
			add("invalid app id %q", a)
		}
	}
	return errors.Join(errs...)
}

// ValidatePassword checks a plaintext Windows password before sealing.
func ValidatePassword(field, pw string) error {
	if strings.ContainsAny(pw, "\r\n\x00") {
		return fmt.Errorf("%s must not contain line breaks", field)
	}
	if len(pw) > 256 {
		return fmt.Errorf("%s is too long", field)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var sshKeyTypes = map[string]bool{
	"ssh-ed25519": true, "ssh-rsa": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true, "sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// checkSSHKey validates an OpenSSH public key line ("type base64 [comment]")
// without options: the type is known and the blob's embedded type matches.
func checkSSHKey(line string) error {
	f := strings.Fields(line)
	if len(f) < 2 || !sshKeyTypes[f[0]] {
		return errors.New("unsupported key type")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 4 {
		return errors.New("bad key data")
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n)+4 > uint64(len(blob)) || string(blob[4:4+n]) != f[0] {
		return errors.New("key data does not match key type")
	}
	return nil
}
