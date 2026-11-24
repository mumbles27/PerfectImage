package packer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"text/template"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"

	"github.com/mumbles27/PerfectImage/internal/catalog"
)

// BuildUsername is the temporary user the installers create for Packer's
// communicator. It matches the build_username default of the catalog
// templates.
const BuildUsername = "packer"

// SeedData is passed to seed templates.
type SeedData struct {
	Username string
	Password string
}

// SeedStore uploads seed ISOs to Proxmox storage and removes them again.
// The integration package implements it on top of the proxmox client and
// installs it with SetSeedStore.
type SeedStore interface {
	// PutSeed uploads iso as storage:iso/name on node and returns the volume
	// id (e.g. "local:iso/pi-seed-x.iso").
	PutSeed(ctx context.Context, cluster, node, storage, name string, iso []byte) (volid string, err error)
	// DeleteSeed removes a volume returned by PutSeed.
	DeleteSeed(ctx context.Context, cluster, node, volid string) error
}

// ErrNoSeedStore is returned when an image needs a seed ISO but no store is
// installed.
var ErrNoSeedStore = errors.New("packer: image needs a seed ISO but no seed store is installed (packer.SetSeedStore)")

var (
	seedMu    sync.RWMutex
	seedStore SeedStore
)

// SetSeedStore installs the process-wide seed store.
func SetSeedStore(s SeedStore) {
	seedMu.Lock()
	defer seedMu.Unlock()
	seedStore = s
}

func currentSeedStore() SeedStore {
	seedMu.RLock()
	defer seedMu.RUnlock()
	return seedStore
}

// RenderSeed renders the image's seed files. The result contains secrets
// (the build password) and must not be logged.
func RenderSeed(img *catalog.Image, data SeedData) (map[string][]byte, error) {
	if img.Seed == nil {
		return nil, nil
	}
	out := make(map[string][]byte, len(img.Seed.Files))
	for _, f := range img.Seed.Files {
		if f.Template == "" {
			out[f.Name] = nil
			continue
		}
		src, err := fs.ReadFile(img.Files, f.Template)
		if err != nil {
			return nil, fmt.Errorf("seed %s: %w", f.Name, err)
		}
		t, err := template.New(f.Name).Funcs(catalog.SeedFuncs).Option("missingkey=error").Parse(string(src))
		if err != nil {
			return nil, fmt.Errorf("seed %s: %w", f.Name, err)
		}
		var b bytes.Buffer
		if err := t.Execute(&b, data); err != nil {
			return nil, fmt.Errorf("seed %s: %w", f.Name, err)
		}
		out[f.Name] = b.Bytes()
	}
	return out, nil
}

// SeedISO builds an ISO 9660 image with Rock Ridge and Joliet names (so
// "user-data" and "ks.cfg" keep their names) and the given volume label.
// It runs in-process: no xorriso/mkisofs/oscdimg is needed on the host.
func SeedISO(label string, files map[string][]byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "pi-seed-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	var size int64 = 1 << 20 // headroom for descriptors and Rock Ridge
	for _, b := range files {
		size += int64(len(b)) + 4096
	}
	imgPath := filepath.Join(dir, "seed.iso")
	d, err := diskfs.Create(imgPath, size, diskfs.SectorSizeDefault)
	if err != nil {
		return nil, fmt.Errorf("seed iso: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = d.Close()
		}
	}()
	d.LogicalBlocksize = 2048
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		return nil, err
	}
	fsys, err := d.CreateFilesystem(disk.FilesystemSpec{
		Partition: 0, FSType: filesystem.TypeISO9660, VolumeLabel: label, WorkDir: work,
	})
	if err != nil {
		return nil, fmt.Errorf("seed iso: %w", err)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := fsys.OpenFile("/"+n, os.O_CREATE|os.O_RDWR)
		if err != nil {
			return nil, fmt.Errorf("seed iso: %s: %w", n, err)
		}
		if _, err := f.Write(files[n]); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("seed iso: %s: %w", n, err)
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	iso, ok := fsys.(*iso9660.FileSystem)
	if !ok {
		return nil, errors.New("seed iso: unexpected filesystem type")
	}
	if err := iso.Finalize(iso9660.FinalizeOptions{RockRidge: true, Joliet: true, VolumeIdentifier: label}); err != nil {
		return nil, fmt.Errorf("seed iso: finalize: %w", err)
	}
	closed = true
	if err := d.Close(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(imgPath)
	if err != nil {
		return nil, err
	}
	spacePadIdentifiers(b)
	return b, nil
}

// spacePadIdentifiers rewrites NUL padding in the system and volume
// identifiers of the primary (type 1) and Joliet supplementary (type 2)
// volume descriptors with spaces, as ECMA-119 requires. go-diskfs pads with
// NULs, which some label lookups (blkid, used by cloud-init and Anaconda to
// find "cidata"/"OEMDRV") do not treat as padding.
func spacePadIdentifiers(iso []byte) {
	const sector = 2048
	for off := 16 * sector; off+sector <= len(iso); off += sector {
		vd := iso[off : off+sector]
		if string(vd[1:6]) != "CD001" || vd[0] == 255 {
			return
		}
		switch vd[0] {
		case 1:
			for _, f := range [][2]int{{8, 40}, {40, 72}} {
				for i := f[1] - 1; i >= f[0] && vd[i] == 0; i-- {
					vd[i] = ' '
				}
			}
		case 2: // UCS-2BE: pad with U+0020
			for _, f := range [][2]int{{8, 40}, {40, 72}} {
				for i := f[1] - 2; i >= f[0] && vd[i] == 0 && vd[i+1] == 0; i -= 2 {
					vd[i+1] = ' '
				}
			}
		}
	}
}
