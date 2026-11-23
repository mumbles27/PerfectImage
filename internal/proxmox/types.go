package proxmox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// FlexInt decodes PVE integers that are sometimes sent as strings.
type FlexInt int64

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = 0
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		b = []byte(strings.TrimSpace(s))
		if len(b) == 0 {
			*f = 0
			return nil
		}
	}
	if v, err := strconv.ParseInt(string(b), 10, 64); err == nil {
		*f = FlexInt(v)
		return nil
	}
	v, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("proxmox: not a number: %s", b)
	}
	*f = FlexInt(v)
	return nil
}

// FlexBool decodes PVE booleans sent as 0/1, "0"/"1" or true/false.
type FlexBool bool

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexBool) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		*f = true
	case "", "0", "false", "no", "off", "null":
		*f = false
	default:
		return fmt.Errorf("proxmox: not a boolean: %s", b)
	}
	return nil
}

// Version is GET /version.
type Version struct {
	Version string `json:"version"`
	Release string `json:"release"`
	RepoID  string `json:"repoid"`
}

// Resource is one entry of GET /cluster/resources.
type Resource struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"` // qemu, lxc, node, storage, pool, sdn
	Node     string   `json:"node"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Storage  string   `json:"storage"`
	Pool     string   `json:"pool"`
	Tags     string   `json:"tags"`
	VMID     FlexInt  `json:"vmid"`
	Template FlexBool `json:"template"`
	MaxCPU   FlexInt  `json:"maxcpu"`
	MaxMem   FlexInt  `json:"maxmem"`
	MaxDisk  FlexInt  `json:"maxdisk"`
	Uptime   FlexInt  `json:"uptime"`
}

// TagList splits the PVE tag string (";" / "," / " " separated).
func (r Resource) TagList() []string { return SplitTags(r.Tags) }

// Node is one entry of GET /nodes.
type Node struct {
	Node   string  `json:"node"`
	Status string  `json:"status"`
	MaxCPU FlexInt `json:"maxcpu"`
	MaxMem FlexInt `json:"maxmem"`
	Mem    FlexInt `json:"mem"`
	Uptime FlexInt `json:"uptime"`
}

// Storage is one entry of GET /nodes/{node}/storage.
type Storage struct {
	Storage string   `json:"storage"`
	Type    string   `json:"type"`
	Content string   `json:"content"`
	Active  FlexBool `json:"active"`
	Enabled FlexBool `json:"enabled"`
	Shared  FlexBool `json:"shared"`
	Avail   FlexInt  `json:"avail"`
	Total   FlexInt  `json:"total"`
}

// StorageContent is one entry of GET /nodes/{node}/storage/{storage}/content.
type StorageContent struct {
	VolID   string  `json:"volid"`
	Content string  `json:"content"`
	Format  string  `json:"format"`
	Size    FlexInt `json:"size"`
	CTime   FlexInt `json:"ctime"`
	VMID    FlexInt `json:"vmid"`
	Notes   string  `json:"notes"`
}

// NetworkIface is one entry of GET /nodes/{node}/network.
type NetworkIface struct {
	Iface     string   `json:"iface"`
	Type      string   `json:"type"`
	Active    FlexBool `json:"active"`
	Comments  string   `json:"comments"`
	VLANAware FlexBool `json:"bridge_vlan_aware"`
}

// VM is one entry of GET /nodes/{node}/qemu.
type VM struct {
	VMID     FlexInt  `json:"vmid"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Tags     string   `json:"tags"`
	Template FlexBool `json:"template"`
	CPUs     FlexInt  `json:"cpus"`
	MaxMem   FlexInt  `json:"maxmem"`
	MaxDisk  FlexInt  `json:"maxdisk"`
	Uptime   FlexInt  `json:"uptime"`
}

// VMStatus is GET /nodes/{node}/qemu/{vmid}/status/current.
type VMStatus struct {
	VMID      FlexInt  `json:"vmid"`
	Name      string   `json:"name"`
	Status    string   `json:"status"` // running, stopped
	QMPStatus string   `json:"qmpstatus"`
	Agent     FlexBool `json:"agent"`
	Lock      string   `json:"lock"`
	Uptime    FlexInt  `json:"uptime"`
	Template  FlexBool `json:"template"`
}

// VMConfig is GET /nodes/{node}/qemu/{vmid}/config. Values are strings or
// numbers depending on the key; use Get.
type VMConfig map[string]any

// Get returns key as a string ("" when absent).
func (c VMConfig) Get(key string) string {
	switch v := c[key].(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "1"
		}
		return "0"
	default:
		return fmt.Sprint(v)
	}
}

// IsTemplate reports template=1.
func (c VMConfig) IsTemplate() bool { return c.Get("template") == "1" }

// Tags returns the VM tags.
func (c VMConfig) Tags() []string { return SplitTags(c.Get("tags")) }

// OSType returns the ostype (l26, win11, ...).
func (c VMConfig) OSType() string { return c.Get("ostype") }

// IsWindows reports whether ostype is a Windows variant.
func (c VMConfig) IsWindows() bool { return strings.HasPrefix(c.OSType(), "w") }

var diskKey = regexp.MustCompile(`^(scsi|virtio|sata|ide)\d+$`)

// Disks returns disk keys (excluding CD-ROMs and cloud-init drives) in a
// stable order.
func (c VMConfig) Disks() []string {
	var out []string
	for k := range c {
		if !diskKey.MatchString(k) {
			continue
		}
		v := c.Get(k)
		if strings.Contains(v, "media=cdrom") || strings.Contains(v, "cloudinit") || v == "none" {
			continue
		}
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// BootDisk returns the primary disk key: the first disk in the boot order,
// else the legacy bootdisk key, else the first disk.
func (c VMConfig) BootDisk() string {
	disks := c.Disks()
	if boot := c.Get("boot"); strings.HasPrefix(boot, "order=") {
		for _, d := range strings.Split(strings.TrimPrefix(boot, "order="), ";") {
			if slices.Contains(disks, d) {
				return d
			}
		}
	}
	if bd := c.Get("bootdisk"); slices.Contains(disks, bd) {
		return bd
	}
	if len(disks) > 0 {
		return disks[0]
	}
	return ""
}

// HasCloudInit reports whether a cloud-init drive is attached.
func (c VMConfig) HasCloudInit() bool {
	for k := range c {
		if diskKey.MatchString(k) && strings.Contains(c.Get(k), "cloudinit") {
			return true
		}
	}
	return false
}

// DiskSizeBytes parses the size= option of a disk value ("local:vm-1-disk-0,size=32G").
func (c VMConfig) DiskSizeBytes(key string) int64 {
	for _, opt := range strings.Split(c.Get(key), ",") {
		if v, ok := strings.CutPrefix(opt, "size="); ok {
			n, _ := ParseSize(v)
			return n
		}
	}
	return 0
}

// ParseSize parses PVE sizes such as 512M, 32G, 1T, or plain bytes.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("proxmox: empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult = 1 << 10
	case 'M', 'm':
		mult = 1 << 20
	case 'G', 'g':
		mult = 1 << 30
	case 'T', 't':
		mult = 1 << 40
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("proxmox: bad size %q", s)
	}
	return int64(f * float64(mult)), nil
}

// SplitTags splits a PVE tag string.
func SplitTags(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' })
	return slices.DeleteFunc(f, func(t string) bool { return t == "" })
}

// TaskStatus is GET /nodes/{node}/tasks/{upid}/status.
type TaskStatus struct {
	UPID       string  `json:"upid"`
	Node       string  `json:"node"`
	Status     string  `json:"status"` // running, stopped
	ExitStatus string  `json:"exitstatus"`
	Type       string  `json:"type"`
	ID         string  `json:"id"`
	User       string  `json:"user"`
	PID        FlexInt `json:"pid"`
	StartTime  FlexInt `json:"starttime"`
}

// Running reports whether the task has not finished yet.
func (t TaskStatus) Running() bool { return t.Status == "running" }

// OK reports whether a finished task succeeded (warnings count as success).
func (t TaskStatus) OK() bool {
	return t.ExitStatus == "OK" || strings.HasPrefix(t.ExitStatus, "WARNINGS")
}

// TaskLogLine is one entry of GET /nodes/{node}/tasks/{upid}/log.
type TaskLogLine struct {
	N int    `json:"n"`
	T string `json:"t"`
}

// UPID is a parsed task identifier
// "UPID:node:pid:pstart:starttime:type:id:user:".
type UPID struct {
	Raw  string
	Node string
	Type string
	ID   string
	User string
}

// ParseUPID parses a task ID.
func ParseUPID(s string) (UPID, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 9 || parts[0] != "UPID" || parts[1] == "" {
		return UPID{}, fmt.Errorf("proxmox: malformed UPID %q", s)
	}
	return UPID{Raw: s, Node: parts[1], Type: parts[5], ID: parts[6], User: parts[7]}, nil
}

// Pool is one entry of GET /pools.
type Pool struct {
	PoolID  string `json:"poolid"`
	Comment string `json:"comment"`
}

// AgentInterface is one entry of agent/network-get-interfaces.
type AgentInterface struct {
	Name            string      `json:"name"`
	HardwareAddress string      `json:"hardware-address"`
	IPAddresses     []AgentAddr `json:"ip-addresses"`
}

// AgentAddr is a guest IP address.
type AgentAddr struct {
	Type    string  `json:"ip-address-type"` // ipv4, ipv6
	Address string  `json:"ip-address"`
	Prefix  FlexInt `json:"prefix"`
}

// ExecStatus is agent/exec-status.
type ExecStatus struct {
	Exited       FlexBool `json:"exited"`
	ExitCode     FlexInt  `json:"exitcode"`
	Signal       FlexInt  `json:"signal"`
	OutData      string   `json:"out-data"`
	ErrData      string   `json:"err-data"`
	OutTruncated FlexBool `json:"out-truncated"`
	ErrTruncated FlexBool `json:"err-truncated"`
}
