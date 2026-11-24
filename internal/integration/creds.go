package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sort"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/packer"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
)

// ProxmoxCreds implements packer.ClusterCreds and packer.Inventory on top of
// the proxmox cluster registry. Secrets are returned only to the packer
// package, which passes them to Packer via environment variables.
//
// Packer's proxmox plugin cannot pin a fingerprint or trust a private CA, so
// for clusters configured with either, Creds hands Packer the URL of a
// loopback proxmox.Relay that performs PerfectImage's own pinned TLS
// verification upstream. TLS verification is never turned off for them.
type ProxmoxCreds struct {
	Registry *proxmox.Registry
	Logger   *slog.Logger

	mu     sync.Mutex
	relays map[string]relayEntry // cluster name -> relay
}

type relayEntry struct {
	key   string // endpoint + TLS settings; a change rebuilds the relay
	relay *proxmox.Relay
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
	if c.Fingerprint == "" && c.CAPEM == "" && c.CAFile == "" {
		// System roots (or explicit insecure): Packer can connect directly.
		return c.Endpoint, c.TokenID, c.Secret, c.InsecureSkipVerify, nil
	}
	r, err := p.relay(c)
	if err != nil {
		return "", "", "", false, err
	}
	return r.URL(), c.TokenID, c.Secret, false, nil
}

func relayKey(c proxmox.Credentials) string {
	h := sha256.New()
	for _, s := range []string{c.Endpoint, c.Fingerprint, c.CAPEM, c.CAFile} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	if c.InsecureSkipVerify {
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// relay returns the running relay for c.Cluster, starting (or replacing) it
// when needed.
func (p *ProxmoxCreds) relay(c proxmox.Credentials) (*proxmox.Relay, error) {
	key := relayKey(c)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.relays == nil {
		p.relays = map[string]relayEntry{}
	}
	if e, ok := p.relays[c.Cluster]; ok {
		if e.key == key {
			return e.relay, nil
		}
		// Settings changed: stop the old relay in the background (a build
		// still using it keeps its connection until Shutdown completes).
		go func(old *proxmox.Relay) { _ = old.Close(context.Background()) }(e.relay)
	}
	r, err := proxmox.StartRelay(proxmox.RelayOptions{
		Endpoint: c.Endpoint, CAPEM: []byte(c.CAPEM), CAFile: c.CAFile,
		Fingerprint: c.Fingerprint, InsecureSkipVerify: c.InsecureSkipVerify,
		Logger: p.Logger,
	})
	if err != nil {
		return nil, err
	}
	p.relays[c.Cluster] = relayEntry{key: key, relay: r}
	return r, nil
}

// Close stops all relays.
func (p *ProxmoxCreds) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for name, e := range p.relays {
		errs = append(errs, e.relay.Close(ctx))
		delete(p.relays, name)
	}
	return errors.Join(errs...)
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
