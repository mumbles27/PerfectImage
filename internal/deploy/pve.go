package deploy

import (
	"context"
	"net/url"
	"time"

	"github.com/mumbles27/PerfectImage/internal/proxmox"
)

// PVE is the subset of *proxmox.Client used by this package (mocked in tests).
type PVE interface {
	Templates(ctx context.Context) ([]proxmox.Resource, error)
	Nodes(ctx context.Context) ([]proxmox.Node, error)
	Storages(ctx context.Context, node, content string) ([]proxmox.Storage, error)
	Networks(ctx context.Context, node, typ string) ([]proxmox.NetworkIface, error)
	Pools(ctx context.Context) ([]proxmox.Pool, error)
	NextID(ctx context.Context) (int, error)

	VMConfig(ctx context.Context, node string, vmid int) (proxmox.VMConfig, error)
	VMStatus(ctx context.Context, node string, vmid int) (proxmox.VMStatus, error)
	Clone(ctx context.Context, node string, vmid int, o proxmox.CloneOptions) (string, error)
	SetConfig(ctx context.Context, node string, vmid int, params url.Values) (string, error)
	ResizeDisk(ctx context.Context, node string, vmid int, disk, size string) (string, error)
	Start(ctx context.Context, node string, vmid int) (string, error)
	Stop(ctx context.Context, node string, vmid int) (string, error)
	Reboot(ctx context.Context, node string, vmid int) (string, error)
	DeleteVM(ctx context.Context, node string, vmid int) (string, error)
	WaitTask(ctx context.Context, upid string) (proxmox.TaskStatus, error)

	AgentPing(ctx context.Context, node string, vmid int) error
	AgentNetworkInterfaces(ctx context.Context, node string, vmid int) ([]proxmox.AgentInterface, error)
	AgentExec(ctx context.Context, node string, vmid int, command []string, input string) (int, error)
	AgentExecStatus(ctx context.Context, node string, vmid, pid int) (proxmox.ExecStatus, error)
	AgentFileWrite(ctx context.Context, node string, vmid int, file, content string) error
}

var _ PVE = (*proxmox.Client)(nil)

// ClientSource returns a PVE client per cluster name.
type ClientSource interface {
	Client(ctx context.Context, cluster string) (PVE, error)
	ClusterNames(ctx context.Context) ([]string, error)
	Cluster(ctx context.Context, name string) (*proxmox.Cluster, error)
}

// RegistrySource adapts a *proxmox.Registry to ClientSource.
type RegistrySource struct{ Reg *proxmox.Registry }

// Client implements ClientSource.
func (s RegistrySource) Client(ctx context.Context, cluster string) (PVE, error) {
	return s.Reg.Client(ctx, cluster)
}

// ClusterNames implements ClientSource.
func (s RegistrySource) ClusterNames(ctx context.Context) ([]string, error) {
	cs, err := s.Reg.Clusters(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out, nil
}

// Cluster implements ClientSource.
func (s RegistrySource) Cluster(ctx context.Context, name string) (*proxmox.Cluster, error) {
	return s.Reg.Store().GetByName(ctx, name)
}

// waitTask waits for upid with a timeout.
func waitTask(ctx context.Context, c PVE, upid string, timeout time.Duration) error {
	if upid == "" {
		return nil
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	_, err := c.WaitTask(ctx, upid)
	return err
}
