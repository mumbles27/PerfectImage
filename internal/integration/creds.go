package integration

import (
	"context"
	"sort"

	"github.com/mumbles27/PerfectImage/internal/packer"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
)

// ProxmoxCreds implements packer.ClusterCreds and packer.Inventory on top of
// the proxmox cluster registry. Secrets are returned only to the packer
// package, which passes them to Packer via environment variables.
type ProxmoxCreds struct {
	Registry *proxmox.Registry
}

var (
	_ packer.ClusterCreds = (*ProxmoxCreds)(nil)
	_ packer.Inventory    = (*ProxmoxCreds)(nil)
)

// Creds implements packer.ClusterCreds.
func (p *ProxmoxCreds) Creds(ctx context.Context, cluster string) (endpoint, tokenID, secret string, insecure bool, err error) {
	c, err := p.Registry.Credentials(ctx, cluster)
	if err != nil {
		return "", "", "", false, err
	}
	return c.Endpoint, c.TokenID, c.Secret, c.InsecureSkipVerify, nil
}

// Clusters implements packer.Inventory.
func (p *ProxmoxCreds) Clusters(ctx context.Context) ([]string, error) {
	cs, err := p.Registry.Clusters(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name)
	}
	return names, nil
}

// Nodes implements packer.Inventory (online nodes first, then by name).
func (p *ProxmoxCreds) Nodes(ctx context.Context, cluster string) ([]string, error) {
	cl, err := p.Registry.Client(ctx, cluster)
	if err != nil {
		return nil, err
	}
	nodes, err := cl.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		oi, oj := nodes[i].Status == "online", nodes[j].Status == "online"
		if oi != oj {
			return oi
		}
		return nodes[i].Node < nodes[j].Node
	})
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Node)
	}
	return out, nil
}

// Storages implements packer.Inventory: storages on node that can hold VM
// disk images.
func (p *ProxmoxCreds) Storages(ctx context.Context, cluster, node string) ([]string, error) {
	cl, err := p.Registry.Client(ctx, cluster)
	if err != nil {
		return nil, err
	}
	sts, err := cl.Storages(ctx, node, "images")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(sts))
	for _, s := range sts {
		out = append(out, s.Storage)
	}
	sort.Strings(out)
	return out, nil
}
