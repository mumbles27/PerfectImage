package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/proxmox"
)

// fakePVE implements PVE in memory.
type fakePVE struct {
	mu        sync.Mutex
	calls     []string
	vms       map[int]proxmox.VMConfig
	running   map[int]bool
	nextID    int
	pings     int
	readyPing int // AgentPing succeeds from this call on (0 = never)
	failOn    map[string]error
	execs     []fakeExec
	files     map[string]string
	exitCode  func(cmd []string, input string, files map[string]string) (int, string)
	setParams url.Values
}

type fakeExec struct {
	Cmd   []string
	Input string
}

func newFakePVE() *fakePVE {
	return &fakePVE{
		vms: map[int]proxmox.VMConfig{
			9000: {"name": "ubuntu-24.04", "template": float64(1), "ostype": "l26", "tags": "perfectimage;ubuntu",
				"scsi0": "local-lvm:base-9000-disk-0,size=10G", "boot": "order=scsi0", "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
				"description": "Built by PerfectImage\nbuild_id: b-123\nimage: ubuntu-24.04\ncommit=abc123"},
			9001: {"name": "win2022", "template": float64(1), "ostype": "win11", "scsi0": "local-lvm:base-9001-disk-0,size=40G",
				"boot": "order=scsi0", "net0": "e1000=AA:BB:CC:DD:EE:00,bridge=vmbr0"},
			500: {"name": "plain-vm", "ostype": "l26"},
		},
		running:   map[int]bool{},
		nextID:    120,
		readyPing: 2,
		failOn:    map[string]error{},
		files:     map[string]string{},
	}
}

func (f *fakePVE) record(format string, a ...any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := fmt.Sprintf(format, a...)
	f.calls = append(f.calls, c)
	name, _, _ := strings.Cut(c, " ")
	return f.failOn[name]
}

func (f *fakePVE) has(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *fakePVE) callNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		n, _, _ := strings.Cut(c, " ")
		if len(out) > 0 && out[len(out)-1] == n {
			continue // collapse polling
		}
		out = append(out, n)
	}
	return out
}

func upid(typ string, id int) string {
	return fmt.Sprintf("UPID:pve1:00000001:00000001:00000001:%s:%d:test@pve:", typ, id)
}

func (f *fakePVE) Templates(context.Context) ([]proxmox.Resource, error) {
	if err := f.record("Templates"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []proxmox.Resource
	for id, c := range f.vms {
		if c.IsTemplate() {
			out = append(out, proxmox.Resource{Type: "qemu", Node: "pve1", VMID: proxmox.FlexInt(id), Name: c.Get("name"),
				Template: true, Tags: c.Get("tags")})
		}
	}
	return out, nil
}

func (f *fakePVE) Nodes(context.Context) ([]proxmox.Node, error) {
	return []proxmox.Node{{Node: "pve1", Status: "online"}, {Node: "pve2", Status: "online"}}, f.record("Nodes")
}

func (f *fakePVE) Storages(_ context.Context, node, _ string) ([]proxmox.Storage, error) {
	return []proxmox.Storage{{Storage: "local-lvm"}, {Storage: "ceph"}}, f.record("Storages %s", node)
}

func (f *fakePVE) Networks(_ context.Context, node, _ string) ([]proxmox.NetworkIface, error) {
	return []proxmox.NetworkIface{{Iface: "vmbr0"}, {Iface: "vmbr1"}}, f.record("Networks %s", node)
}

func (f *fakePVE) Pools(context.Context) ([]proxmox.Pool, error) {
	return []proxmox.Pool{{PoolID: "perfectimage"}}, f.record("Pools")
}

func (f *fakePVE) NextID(context.Context) (int, error) {
	err := f.record("NextID")
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nextID, err
}

func (f *fakePVE) VMConfig(_ context.Context, node string, vmid int) (proxmox.VMConfig, error) {
	if err := f.record("VMConfig %d", vmid); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.vms[vmid]
	if !ok {
		return nil, &proxmox.APIError{StatusCode: 500, Message: "Configuration file does not exist"}
	}
	out := proxmox.VMConfig{}
	for k, v := range c {
		out[k] = v
	}
	return out, nil
}

func (f *fakePVE) VMStatus(_ context.Context, _ string, vmid int) (proxmox.VMStatus, error) {
	err := f.record("VMStatus %d", vmid)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.vms[vmid]; !ok {
		return proxmox.VMStatus{}, &proxmox.APIError{StatusCode: 500, Message: "does not exist"}
	}
	st := "stopped"
	if f.running[vmid] {
		st = "running"
	}
	return proxmox.VMStatus{Status: st}, err
}

func (f *fakePVE) Clone(_ context.Context, node string, vmid int, o proxmox.CloneOptions) (string, error) {
	if err := f.record("Clone %d->%d full=%v target=%s storage=%s pool=%s", vmid, o.NewID, o.Full, o.Target, o.Storage, o.Pool); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	nc := proxmox.VMConfig{}
	for k, v := range f.vms[vmid] {
		nc[k] = v
	}
	delete(nc, "template")
	nc["name"] = o.Name
	f.vms[o.NewID] = nc
	return upid("qmclone", o.NewID), nil
}

func (f *fakePVE) SetConfig(_ context.Context, _ string, vmid int, p url.Values) (string, error) {
	if err := f.record("SetConfig %d", vmid); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setParams = p
	for k := range p {
		f.vms[vmid][k] = p.Get(k)
	}
	return "", nil
}

func (f *fakePVE) ResizeDisk(_ context.Context, _ string, vmid int, disk, size string) (string, error) {
	return upid("resize", vmid), f.record("ResizeDisk %d %s %s", vmid, disk, size)
}

func (f *fakePVE) Start(_ context.Context, _ string, vmid int) (string, error) {
	err := f.record("Start %d", vmid)
	f.mu.Lock()
	f.running[vmid] = true
	f.mu.Unlock()
	return upid("qmstart", vmid), err
}

func (f *fakePVE) Stop(_ context.Context, _ string, vmid int) (string, error) {
	err := f.record("Stop %d", vmid)
	f.mu.Lock()
	f.running[vmid] = false
	f.mu.Unlock()
	return upid("qmstop", vmid), err
}

func (f *fakePVE) Reboot(_ context.Context, _ string, vmid int) (string, error) {
	err := f.record("Reboot %d", vmid)
	f.mu.Lock()
	f.pings = 0
	f.mu.Unlock()
	return upid("qmreboot", vmid), err
}

func (f *fakePVE) DeleteVM(_ context.Context, _ string, vmid int) (string, error) {
	if err := f.record("DeleteVM %d", vmid); err != nil {
		return "", err
	}
	f.mu.Lock()
	delete(f.vms, vmid)
	f.mu.Unlock()
	return upid("qmdestroy", vmid), nil
}

func (f *fakePVE) WaitTask(_ context.Context, u string) (proxmox.TaskStatus, error) {
	err := f.record("WaitTask %s", u)
	return proxmox.TaskStatus{Status: "stopped", ExitStatus: "OK"}, err
}

func (f *fakePVE) AgentPing(_ context.Context, _ string, vmid int) error {
	if err := f.record("AgentPing %d", vmid); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings++
	if f.readyPing == 0 || f.pings < f.readyPing {
		return &proxmox.APIError{StatusCode: 500, Message: "QEMU guest agent is not running"}
	}
	return nil
}

func (f *fakePVE) AgentNetworkInterfaces(_ context.Context, _ string, vmid int) ([]proxmox.AgentInterface, error) {
	return []proxmox.AgentInterface{
		{Name: "lo", IPAddresses: []proxmox.AgentAddr{{Type: "ipv4", Address: "127.0.0.1"}}},
		{Name: "eth0", IPAddresses: []proxmox.AgentAddr{{Type: "ipv4", Address: "10.0.10.25"}, {Type: "ipv6", Address: "fe80::1"}}},
	}, f.record("AgentNetworkInterfaces %d", vmid)
}

func (f *fakePVE) AgentExec(_ context.Context, _ string, vmid int, cmd []string, input string) (int, error) {
	if err := f.record("AgentExec %d %s", vmid, strings.Join(cmd, " ")); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, fakeExec{Cmd: cmd, Input: input})
	return len(f.execs), nil
}

func (f *fakePVE) AgentExecStatus(_ context.Context, _ string, vmid, pid int) (proxmox.ExecStatus, error) {
	if err := f.record("AgentExecStatus %d %d", vmid, pid); err != nil {
		return proxmox.ExecStatus{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.execs[pid-1]
	code, out := 0, "ok\n"
	if f.exitCode != nil {
		code, out = f.exitCode(e.Cmd, e.Input, f.files)
	} else if e.Input == "exit 3" {
		code, out = 3, "failing on purpose\n"
	}
	return proxmox.ExecStatus{Exited: true, ExitCode: proxmox.FlexInt(code), OutData: out}, nil
}

func (f *fakePVE) AgentFileWrite(_ context.Context, _ string, vmid int, file, content string) error {
	if err := f.record("AgentFileWrite %d %s", vmid, file); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[file] = content
	return nil
}

type fakeSource struct {
	c        *fakePVE
	clusters map[string]*proxmox.Cluster
}

func newFakeSource(c *fakePVE) *fakeSource {
	return &fakeSource{c: c, clusters: map[string]*proxmox.Cluster{
		"lab": {Name: "lab", DefaultNode: "pve1", DefaultStorage: "local-lvm", DefaultBridge: "vmbr0", DefaultPool: "perfectimage"},
	}}
}

func (s *fakeSource) Client(_ context.Context, name string) (PVE, error) {
	if _, ok := s.clusters[name]; !ok {
		return nil, proxmox.ErrClusterNotFound
	}
	return s.c, nil
}

func (s *fakeSource) ClusterNames(context.Context) ([]string, error) { return []string{"lab"}, nil }

func (s *fakeSource) Cluster(_ context.Context, name string) (*proxmox.Cluster, error) {
	c, ok := s.clusters[name]
	if !ok {
		return nil, proxmox.ErrClusterNotFound
	}
	return c, nil
}

// memLog collects job log lines.
type memLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *memLog) Printf(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, a...))
}

func (l *memLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

var errBoom = errors.New("boom")
