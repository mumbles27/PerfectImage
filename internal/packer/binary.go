package packer

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/config"
)

// ErrNoBinary is returned when packer cannot be found or downloaded.
var ErrNoBinary = errors.New("packer: binary not found (set packer.binary, put packer in PATH or set packer.version)")

const maxZipBytes = 512 << 20

var downloadMu sync.Mutex

func exeName() string {
	if runtime.GOOS == "windows" {
		return "packer.exe"
	}
	return "packer"
}

// FindBinary locates the packer executable: packer.binary, then PATH, then
// a pinned packer.version downloaded (and checksum-verified) into
// <work_dir>/bin/<version>/.
func FindBinary(ctx context.Context, cfg config.PackerConfig, client *http.Client) (string, error) {
	if cfg.Binary != "" {
		if _, err := os.Stat(cfg.Binary); err != nil {
			return "", fmt.Errorf("packer.binary: %w", err)
		}
		return cfg.Binary, nil
	}
	if p, err := exec.LookPath("packer"); err == nil {
		return p, nil
	}
	if cfg.Version == "" {
		return "", ErrNoBinary
	}
	return Download(ctx, cfg, client)
}

// Download fetches the pinned packer release for this platform into
// <work_dir>/bin/<version>/ unless it is already there. The zip's SHA-256
// must match packer.version_sha256 or, when that is empty, the release's
// SHA256SUMS file.
func Download(ctx context.Context, cfg config.PackerConfig, client *http.Client) (string, error) {
	downloadMu.Lock()
	defer downloadMu.Unlock()
	if client == nil {
		client = http.DefaultClient
	}
	dir := filepath.Join(cfg.WorkDir, "bin", cfg.Version)
	dst := filepath.Join(dir, exeName())
	if _, err := os.Stat(dst); err == nil {
		return dst, nil
	}
	base := strings.TrimRight(cfg.ReleasesURL, "/") + "/packer/" + cfg.Version + "/"
	zipName := fmt.Sprintf("packer_%s_%s_%s.zip", cfg.Version, runtime.GOOS, runtime.GOARCH)

	want := strings.ToLower(cfg.VersionSHA256)
	if want == "" {
		sums, err := fetch(ctx, client, base+"packer_"+cfg.Version+"_SHA256SUMS", 1<<20)
		if err != nil {
			return "", fmt.Errorf("packer: download checksums: %w", err)
		}
		if want = findSum(sums, zipName); want == "" {
			return "", fmt.Errorf("packer: %s not listed in SHA256SUMS", zipName)
		}
	}
	zb, err := fetch(ctx, client, base+zipName, maxZipBytes)
	if err != nil {
		return "", fmt.Errorf("packer: download %s: %w", zipName, err)
	}
	sum := sha256.Sum256(zb)
	if got := hex.EncodeToString(sum[:]); got != want {
		return "", fmt.Errorf("packer: checksum mismatch for %s: got %s, want %s", zipName, got, want)
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		return "", fmt.Errorf("packer: open zip: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != exeName() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		tmp, err := os.CreateTemp(dir, ".packer-*")
		if err != nil {
			return "", err
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, io.LimitReader(rc, maxZipBytes)); err != nil {
			tmp.Close()
			return "", err
		}
		if err := tmp.Chmod(0o700); err != nil && runtime.GOOS != "windows" {
			tmp.Close()
			return "", err
		}
		if err := tmp.Close(); err != nil {
			return "", err
		}
		if err := os.Rename(tmp.Name(), dst); err != nil {
			return "", err
		}
		return dst, nil
	}
	return "", fmt.Errorf("packer: %s does not contain %s", zipName, exeName())
}

func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: response too large", url)
	}
	return b, nil
}

func findSum(sums []byte, name string) string {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0])
		}
	}
	return ""
}
