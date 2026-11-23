package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestFormat is the archive manifest version this binary writes/reads.
const ManifestFormat = 1

// Archive entry names.
const (
	entryManifest  = "manifest.json"
	entryDB        = "perfectimage.db"
	entryConfig    = "config.yaml"
	entryMasterKey = "secrets/master.key"
	catalogPrefix  = "catalog/"
)

// maxExtractSize bounds the total extracted size (decompression bombs).
const maxExtractSize = 64 << 30

// FileEntry is one file recorded in the manifest.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest describes an archive. It is the last tar entry.
type Manifest struct {
	Format            int            `json:"format"`
	AppVersion        string         `json:"app_version"`
	CreatedAt         time.Time      `json:"created_at"`
	Host              string         `json:"host"`
	Schema            map[string]int `json:"schema_versions"`
	IncludesMasterKey bool           `json:"includes_master_key"`
	ConfigPath        string         `json:"config_path,omitempty"`
	// CatalogDirs are the source catalog directories; directory i is stored
	// under catalog/<i>/.
	CatalogDirs []string    `json:"catalog_dirs,omitempty"`
	Files       []FileEntry `json:"files"`
}

// HasFile reports whether the manifest lists name.
func (m *Manifest) HasFile(name string) bool {
	for _, f := range m.Files {
		if f.Path == name {
			return true
		}
	}
	return false
}

// archiveWriter streams a tar.gz into an encrypting writer, hashing files.
type archiveWriter struct {
	tw    *tar.Writer
	gz    *gzip.Writer
	enc   io.WriteCloser
	files []FileEntry
	now   time.Time
}

func newArchiveWriter(w io.Writer, passphrase []byte, kdf KDFParams, now time.Time) (*archiveWriter, error) {
	enc, err := newEncryptWriter(w, passphrase, kdf)
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(enc)
	return &archiveWriter{tw: tar.NewWriter(gz), gz: gz, enc: enc, now: now}, nil
}

func (a *archiveWriter) addReader(name string, size int64, r io.Reader) error {
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: a.now, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := a.tw.WriteHeader(hdr); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(a.tw, io.TeeReader(io.LimitReader(r, size), h))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("backup: %s changed while archiving (%d of %d bytes)", name, n, size)
	}
	a.files = append(a.files, FileEntry{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

func (a *archiveWriter) addFile(name, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return a.addReader(name, fi.Size(), f)
}

func (a *archiveWriter) addBytes(name string, b []byte) error {
	return a.addReader(name, int64(len(b)), strings.NewReader(string(b)))
}

// addDir archives the regular files under dir as prefix/<rel>. Symlinks and
// special files are skipped.
func (a *archiveWriter) addDir(prefix, dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		return a.addFile(prefix+filepath.ToSlash(rel), p)
	})
}

// finish writes the manifest and closes every layer.
func (a *archiveWriter) finish(m *Manifest) error {
	m.Files = a.files
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: entryManifest, Mode: 0o600, Size: int64(len(b)), ModTime: a.now, Typeflag: tar.TypeReg}
	if err := a.tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := a.tw.Write(b); err != nil {
		return err
	}
	if err := a.tw.Close(); err != nil {
		return err
	}
	if err := a.gz.Close(); err != nil {
		return err
	}
	return a.enc.Close()
}

// safeName validates an archive entry name and returns its OS path under dir.
func safeName(dir, name string) (string, error) {
	if name == "" || strings.Contains(name, `\`) || path.IsAbs(name) || strings.Contains(name, ":") {
		return "", fmt.Errorf("%w: unsafe entry name %q", ErrCorrupt, name)
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: unsafe entry name %q", ErrCorrupt, name)
	}
	switch {
	case clean == entryDB, clean == entryConfig, clean == entryMasterKey, clean == entryManifest:
	case strings.HasPrefix(clean, catalogPrefix):
	default:
		return "", fmt.Errorf("%w: unexpected entry %q", ErrCorrupt, name)
	}
	return filepath.Join(dir, filepath.FromSlash(clean)), nil
}

// extract decrypts src into dir (which must exist and be empty) and checks
// every file against the manifest. Nothing outside dir is touched.
func extract(src io.Reader, passphrase []byte, dir string) (*Manifest, error) {
	dec, err := newDecryptReader(src, passphrase)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(dec)
	if err != nil {
		return nil, corrupt(err)
	}
	tr := tar.NewReader(gz)
	got := map[string]FileEntry{}
	var manifest *Manifest
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, corrupt(err)
		}
		if manifest != nil {
			return nil, fmt.Errorf("%w: entries after manifest", ErrCorrupt)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: entry %q is not a regular file", ErrCorrupt, hdr.Name)
		}
		if _, dup := got[hdr.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate entry %q", ErrCorrupt, hdr.Name)
		}
		total += hdr.Size
		if hdr.Size < 0 || total > maxExtractSize {
			return nil, fmt.Errorf("%w: archive too large", ErrCorrupt)
		}
		if hdr.Name == entryManifest {
			b, err := io.ReadAll(io.LimitReader(tr, 16<<20))
			if err != nil {
				return nil, corrupt(err)
			}
			manifest = &Manifest{}
			if err := json.Unmarshal(b, manifest); err != nil {
				return nil, fmt.Errorf("%w: manifest: %v", ErrCorrupt, err)
			}
			continue
		}
		dst, err := safeName(dir, hdr.Name)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, h), tr)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, corrupt(err)
		}
		got[hdr.Name] = FileEntry{Path: hdr.Name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
	}
	// Read to the authenticated end of the encrypted stream (detects
	// truncation and trailing data).
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return nil, corrupt(err)
	}
	if _, err := io.Copy(io.Discard, dec); err != nil {
		return nil, corrupt(err)
	}
	if manifest == nil {
		return nil, fmt.Errorf("%w: manifest missing", ErrCorrupt)
	}
	if manifest.Format != ManifestFormat {
		return nil, fmt.Errorf("backup: unsupported manifest format %d (this binary reads %d)", manifest.Format, ManifestFormat)
	}
	if len(manifest.Files) != len(got) {
		return nil, fmt.Errorf("%w: manifest lists %d files, archive has %d", ErrCorrupt, len(manifest.Files), len(got))
	}
	for _, f := range manifest.Files {
		g, ok := got[f.Path]
		if !ok || g.Size != f.Size || g.SHA256 != f.SHA256 {
			return nil, fmt.Errorf("%w: %s does not match the manifest", ErrCorrupt, f.Path)
		}
	}
	if _, ok := got[entryDB]; !ok {
		return nil, fmt.Errorf("%w: database snapshot missing", ErrCorrupt)
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	return manifest, nil
}

func corrupt(err error) error {
	if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrWrongPassphrase) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrCorrupt, err)
}
