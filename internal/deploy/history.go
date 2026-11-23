package deploy

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/store"
)

// Deployment statuses.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

// Deployment is a history row.
type Deployment struct {
	JobID       string
	Cluster     string
	Node        string
	VMID        int
	Name        string
	Template    string
	OS          string
	Apps        []string
	Status      string
	Error       string
	IPAddresses string
	CleanedUp   bool
	RequestedBy string
	CreatedAt   time.Time
	FinishedAt  *time.Time
}

// History records deployments. Implementations must tolerate unknown job IDs.
type History interface {
	Queued(ctx context.Context, jobID string, req Request, actor string) error
	Running(ctx context.Context, jobID string, req Request, actor, node string, vmid int) error
	Finished(ctx context.Context, jobID, status, errMsg string, ips []string, cleanedUp bool) error
}

// HistoryStore persists History in deploy_deployments.
type HistoryStore struct{ db *store.DB }

// NewHistoryStore returns a HistoryStore.
func NewHistoryStore(db *store.DB) *HistoryStore { return &HistoryStore{db: db} }

func templateLabel(r Request) string {
	if r.TemplateName != "" {
		return r.TemplateName + " (" + itoa(r.TemplateVMID) + ")"
	}
	return itoa(r.TemplateVMID)
}

func (h *HistoryStore) upsert(ctx context.Context, jobID string, req Request, actor, node string, vmid int, status string) error {
	apps, _ := json.Marshal(req.Apps)
	if req.Apps == nil {
		apps = []byte("[]")
	}
	_, err := h.db.ExecContext(ctx, `INSERT INTO deploy_deployments
		(job_id, cluster, node, vmid, name, template, os, apps, status, requested_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(job_id) DO UPDATE SET node = excluded.node, vmid = excluded.vmid, status = excluded.status`,
		jobID, req.Cluster, node, vmid, req.Name, templateLabel(req), req.OS, string(apps), status, actor,
		time.Now().UTC().UnixMilli())
	return err
}

// Queued implements History.
func (h *HistoryStore) Queued(ctx context.Context, jobID string, req Request, actor string) error {
	return h.upsert(ctx, jobID, req, actor, req.Node, req.VMID, StatusQueued)
}

// Running implements History.
func (h *HistoryStore) Running(ctx context.Context, jobID string, req Request, actor, node string, vmid int) error {
	return h.upsert(ctx, jobID, req, actor, node, vmid, StatusRunning)
}

// Finished implements History.
func (h *HistoryStore) Finished(ctx context.Context, jobID, status, errMsg string, ips []string, cleanedUp bool) error {
	_, err := h.db.ExecContext(ctx, `UPDATE deploy_deployments SET status = ?, error = ?, ip_addresses = ?,
		cleaned_up = ?, finished_at = ? WHERE job_id = ?`,
		status, errMsg, strings.Join(ips, ", "), cleanedUp, time.Now().UTC().UnixMilli(), jobID)
	return err
}

// List returns the newest deployments first.
func (h *HistoryStore) List(ctx context.Context, limit int) ([]Deployment, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := h.db.QueryContext(ctx, `SELECT job_id, cluster, node, vmid, name, template, os, apps, status,
		error, ip_addresses, cleaned_up, requested_by, created_at, finished_at
		FROM deploy_deployments ORDER BY created_at DESC, job_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Deployment
	for rows.Next() {
		var d Deployment
		var apps string
		var created int64
		var finished *int64
		if err := rows.Scan(&d.JobID, &d.Cluster, &d.Node, &d.VMID, &d.Name, &d.Template, &d.OS, &apps, &d.Status,
			&d.Error, &d.IPAddresses, &d.CleanedUp, &d.RequestedBy, &created, &finished); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(apps), &d.Apps)
		d.CreatedAt = time.UnixMilli(created).UTC()
		if finished != nil {
			t := time.UnixMilli(*finished).UTC()
			d.FinishedAt = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type nopHistory struct{}

func (nopHistory) Queued(context.Context, string, Request, string) error               { return nil }
func (nopHistory) Running(context.Context, string, Request, string, string, int) error { return nil }
func (nopHistory) Finished(context.Context, string, string, string, []string, bool) error {
	return nil
}
