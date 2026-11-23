package packer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// BuildRequest is the packer.build job payload. It never contains secrets.
type BuildRequest struct {
	BuildID       string   `json:"build_id"`
	ImageID       string   `json:"image_id"`
	Cluster       string   `json:"cluster"`
	Node          string   `json:"node"`
	Storage       string   `json:"storage,omitempty"`
	ISOStorage    string   `json:"iso_storage,omitempty"`
	Bridge        string   `json:"bridge,omitempty"`
	Cores         int      `json:"cores,omitempty"`
	Memory        int      `json:"memory,omitempty"`
	Disk          string   `json:"disk,omitempty"`
	ISOFile       string   `json:"iso_file,omitempty"`
	VirtioISOFile string   `json:"virtio_iso_file,omitempty"`
	Apps          []string `json:"apps,omitempty"`
	Bundles       []string `json:"bundles,omitempty"`
	// SkipDefaultApps leaves out the image's default_apps.
	SkipDefaultApps bool   `json:"skip_default_apps,omitempty"`
	TemplateName    string `json:"template_name"`
	VMID            int    `json:"vm_id,omitempty"`
}

var (
	pveNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	vmNameRE   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$`)
	diskSizeRE = regexp.MustCompile(`^[1-9][0-9]{0,5}[GMT]$`)
	isoFileRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*:iso/[A-Za-z0-9._+-]+\.iso$`)
)

// FieldErrors maps form fields to messages.
type FieldErrors map[string]string

func (f FieldErrors) Error() string {
	return fmt.Sprintf("invalid build request (%d field error(s))", len(f))
}

// Check validates the request against the catalog and returns the image
// and the resolved app ids (image defaults + apps + bundle members).
func (r *BuildRequest) Check(c *catalog.Catalog) (*catalog.Image, []catalog.InstallStep, error) {
	fe := FieldErrors{}
	img, ok := c.Images[r.ImageID]
	if !ok {
		fe["image_id"] = "Unknown image."
	}
	if !pveNameRE.MatchString(r.Cluster) {
		fe["cluster"] = "Choose a cluster."
	}
	if !pveNameRE.MatchString(r.Node) {
		fe["node"] = "Enter a valid node name."
	}
	for field, v := range map[string]string{"storage": r.Storage, "iso_storage": r.ISOStorage, "bridge": r.Bridge} {
		if v != "" && !pveNameRE.MatchString(v) {
			fe[field] = "Invalid name."
		}
	}
	if r.Cores < 0 || r.Cores > 256 {
		fe["cores"] = "Must be between 1 and 256."
	}
	if r.Memory != 0 && (r.Memory < 512 || r.Memory > 4<<20) {
		fe["memory"] = "Must be at least 512 MiB."
	}
	if r.Disk != "" && !diskSizeRE.MatchString(r.Disk) {
		fe["disk"] = "Use a size like 32G."
	}
	if r.ISOFile != "" && !isoFileRE.MatchString(r.ISOFile) {
		fe["iso_file"] = "Use storage:iso/file.iso."
	}
	if r.VirtioISOFile != "" && !isoFileRE.MatchString(r.VirtioISOFile) {
		fe["virtio_iso_file"] = "Use storage:iso/file.iso."
	}
	if !vmNameRE.MatchString(r.TemplateName) {
		fe["template_name"] = "Letters, digits, dots and dashes (max 63)."
	}
	if r.VMID != 0 && (r.VMID < 100 || r.VMID > 999999999) {
		fe["vm_id"] = "Use 0 (next free) or 100-999999999."
	}
	if img != nil && img.OSFamily == catalog.Windows && r.ISOFile == "" && img.ISO.File == "" {
		fe["iso_file"] = "Windows images need an install ISO on Proxmox storage."
	}
	if len(fe) > 0 {
		return nil, nil, fe
	}
	ids := r.AppIDs(img)
	steps, err := c.Resolve(img.OSFamily, img.DistroFamily, ids)
	if err != nil {
		return nil, nil, FieldErrors{"apps": err.Error()}
	}
	return img, steps, nil
}

// AppIDs returns the requested app and bundle ids, image defaults first.
func (r *BuildRequest) AppIDs(img *catalog.Image) []string {
	var ids []string
	if !r.SkipDefaultApps && img != nil {
		ids = append(ids, img.DefaultApps...)
	}
	ids = append(ids, r.Apps...)
	return append(ids, r.Bundles...)
}

// BuildResult is stored as the job result.
type BuildResult struct {
	BuildID      string   `json:"build_id"`
	ImageID      string   `json:"image_id"`
	TemplateName string   `json:"template_name"`
	TemplateID   string   `json:"template_id,omitempty"`
	Cluster      string   `json:"cluster"`
	Node         string   `json:"node"`
	Apps         []string `json:"apps"`
	Duration     string   `json:"duration"`
}

// Build is a row of packer_builds.
type Build struct {
	ID           string
	JobID        string
	ImageID      string
	ImageName    string
	OSFamily     string
	Cluster      string
	Node         string
	TemplateName string
	VMID         int
	Request      BuildRequest
	Apps         []string
	Status       jobs.Status
	ArtifactID   string
	Error        string
	WorkDir      string
	CreatedBy    string
	CreatedAt    time.Time
	StartedAt    *time.Time
	FinishedAt   *time.Time
}

// Duration is the build run time.
func (b *Build) Duration() time.Duration {
	if b.StartedAt == nil {
		return 0
	}
	end := time.Now()
	if b.FinishedAt != nil {
		end = *b.FinishedAt
	}
	return end.Sub(*b.StartedAt).Round(time.Second)
}

// ErrBuildNotFound is returned for unknown build ids.
var ErrBuildNotFound = errors.New("packer: build not found")

// buildStore persists packer_builds.
type buildStore struct{ db *store.DB }

func newBuildID() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102t150405") + "-" + hex.EncodeToString(b[:])
}

func ms(t time.Time) int64 { return t.UTC().UnixMilli() }

func (s buildStore) insert(ctx context.Context, b *Build) error {
	req, _ := json.Marshal(b.Request)
	apps, _ := json.Marshal(b.Apps)
	_, err := s.db.ExecContext(ctx, `INSERT INTO packer_builds
		(id, job_id, image_id, image_name, os_family, cluster, node, template_name, vm_id, request, apps,
		 status, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.JobID, b.ImageID, b.ImageName, b.OSFamily, b.Cluster, b.Node, b.TemplateName, b.VMID,
		string(req), string(apps), string(b.Status), b.CreatedBy, ms(b.CreatedAt))
	return err
}

func (s buildStore) setJob(ctx context.Context, id, jobID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE packer_builds SET job_id = ? WHERE id = ?`, jobID, id)
	return err
}

func (s buildStore) start(ctx context.Context, id, workdir, sealedPassword string, apps []string) error {
	a, _ := json.Marshal(apps)
	_, err := s.db.ExecContext(ctx, `UPDATE packer_builds
		SET status = 'running', started_at = ?, workdir = ?, build_password = ?, apps = ? WHERE id = ?`,
		ms(time.Now()), workdir, sealedPassword, string(a), id)
	return err
}

func (s buildStore) finish(ctx context.Context, id string, status jobs.Status, artifact, errMsg, workdir string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE packer_builds
		SET status = ?, artifact_id = ?, error = ?, workdir = ?, finished_at = ? WHERE id = ?`,
		string(status), artifact, errMsg, workdir, ms(time.Now()), id)
	return err
}

const buildCols = `id, job_id, image_id, image_name, os_family, cluster, node, template_name, vm_id,
	request, apps, status, artifact_id, error, workdir, created_by, created_at, started_at, finished_at`

type scanner interface{ Scan(...any) error }

func scanBuild(sc scanner) (*Build, error) {
	var (
		b                 Build
		req, apps, status string
		created           int64
		started, finished sql.NullInt64
	)
	if err := sc.Scan(&b.ID, &b.JobID, &b.ImageID, &b.ImageName, &b.OSFamily, &b.Cluster, &b.Node,
		&b.TemplateName, &b.VMID, &req, &apps, &status, &b.ArtifactID, &b.Error, &b.WorkDir,
		&b.CreatedBy, &created, &started, &finished); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(req), &b.Request)
	_ = json.Unmarshal([]byte(apps), &b.Apps)
	b.Status = jobs.Status(status)
	b.CreatedAt = time.UnixMilli(created).UTC()
	if started.Valid {
		t := time.UnixMilli(started.Int64).UTC()
		b.StartedAt = &t
	}
	if finished.Valid {
		t := time.UnixMilli(finished.Int64).UTC()
		b.FinishedAt = &t
	}
	return &b, nil
}

func (s buildStore) get(ctx context.Context, id string) (*Build, error) {
	b, err := scanBuild(s.db.QueryRowContext(ctx, `SELECT `+buildCols+` FROM packer_builds WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrBuildNotFound
	}
	return b, err
}

func (s buildStore) list(ctx context.Context, limit int) ([]*Build, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+buildCols+` FROM packer_builds ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Build
	for rows.Next() {
		b, err := scanBuild(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s buildStore) sealedPassword(ctx context.Context, id string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT build_password FROM packer_builds WHERE id = ?`, id).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrBuildNotFound
	}
	return v, err
}
