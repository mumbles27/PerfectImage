package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/packer"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// TestMediaInventory checks the wizard's bridge/ISO/defaults lookups
// against a fake PVE API.
func TestMediaInventory(t *testing.T) {
	data := map[string]any{
		"/api2/json/nodes/pve1/network": []map[string]any{
			{"iface": "vmbr1", "type": "bridge"}, {"iface": "vmbr0", "type": "OVSBridge"},
		},
		"/api2/json/nodes/pve1/storage": []map[string]any{
			{"storage": "nas", "content": "iso,backup"}, {"storage": "local", "content": "iso,vztmpl"},
		},
		"/api2/json/nodes/pve1/storage/local/content": []map[string]any{
			{"volid": "local:iso/virtio-win.iso", "content": "iso"},
			{"volid": "local:iso/pi-seed-abc123.iso", "content": "iso"}, // PerfectImage's own temporary seed
			{"volid": "local:iso/en-us_windows_server_2025.iso", "content": "iso"},
		},
	}
	var queries = map[string]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries[r.URL.Path] = r.URL.RawQuery
		v, ok := data[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
	}))
	defer srv.Close()

	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "pi.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	key, _ := secrets.NewKey()
	sealer, _ := secrets.NewAESGCM(key)
	reg := proxmox.NewRegistry(db, sealer, nil, config.ProxmoxConfig{})
	if _, err := reg.Store().Create(ctx, proxmox.ClusterInput{
		Name: "lab", Endpoint: srv.URL, TokenID: "fake@pve!test", Secret: "00000000-0000-0000-0000-000000000000",
		InsecureSkipVerify: true, DefaultNode: "pve1", DefaultStorage: "local-zfs", DefaultBridge: "vmbr1",
	}); err != nil {
		t.Fatal(err)
	}
	p := &ProxmoxCreds{Registry: reg}
	defer p.Close(ctx)

	bridges, err := p.Bridges(ctx, "lab", "pve1")
	if err != nil || !slices.Equal(bridges, []string{"vmbr0", "vmbr1"}) {
		t.Fatalf("bridges %v %v", bridges, err)
	}
	if q := queries["/api2/json/nodes/pve1/network"]; q != "type=any_bridge" {
		t.Fatalf("network query %q", q)
	}
	sts, err := p.ISOStorages(ctx, "lab", "pve1")
	if err != nil || !slices.Equal(sts, []string{"local", "nas"}) {
		t.Fatalf("iso storages %v %v", sts, err)
	}
	isos, err := p.ISOs(ctx, "lab", "pve1", "local")
	if err != nil || !slices.Equal(isos, []string{"local:iso/en-us_windows_server_2025.iso", "local:iso/virtio-win.iso"}) {
		t.Fatalf("isos %v %v", isos, err)
	}
	defs, err := p.Defaults(ctx, "lab")
	if err != nil || defs != (packer.TargetDefaults{Node: "pve1", Storage: "local-zfs", Bridge: "vmbr1"}) {
		t.Fatalf("defaults %+v %v", defs, err)
	}
	if _, err := p.Defaults(ctx, "nope"); err == nil {
		t.Fatal("unknown cluster: want error")
	}
}
