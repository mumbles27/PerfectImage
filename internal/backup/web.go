package backup

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

// RestoreConfirmation must be typed to confirm an upload restore.
const RestoreConfirmation = "RESTORE"

type module struct{ svc *Ops }

func (m *module) Name() string { return "backup" }

func (m *module) Templates() fs.FS {
	sub, _ := fs.Sub(templatesFS, "templates")
	return sub
}

func (m *module) Nav() []web.NavItem {
	return []web.NavItem{{Label: "Backup", Path: "/settings/backup", Permission: rbac.BackupRun, Order: 73}}
}

func (m *module) Routes(rt *web.Router) {
	rt.HandleFunc("GET /settings/backup", rbac.BackupRun, m.page(rt))
	rt.HandleFunc("POST /settings/backup/run", rbac.BackupRun, m.run(rt))
	rt.HandleFunc("GET /settings/backup/download/{name}", rbac.BackupRun, m.download(rt))
	rt.HandleFunc("POST /settings/backup/passphrase", rbac.SettingsManage, m.passphrase(rt))
	rt.HandleFunc("POST /settings/backup/restore", rbac.SettingsManage, m.restore(rt))
}

type pageData struct {
	Backups          []Info
	CopyTo           string
	Dir              string
	Schedule         string
	Retention        int
	IncludeMasterKey bool
	HasPassphrase    bool
	RestartRequired  string
	MinPassphrase    int
	MaxUploadMB      int
	Confirmation     string
}

func (m *module) page(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := List(m.svc.cfg.Backup.Dir)
		if err != nil {
			rt.Server().Logger().Error("list backups", "component", "backup", "err", err)
		}
		c := m.svc.cfg.Backup
		rt.Render(w, r, "backup/backup.html", "Backup & restore", pageData{
			Backups: list, Dir: c.Dir, CopyTo: c.CopyTo, Schedule: c.Schedule, Retention: c.Retention,
			IncludeMasterKey: c.MasterKeyIncluded(), HasPassphrase: m.svc.HasPassphrase(r.Context()),
			RestartRequired: m.svc.RestartRequired(), MinPassphrase: MinPassphraseLen,
			MaxUploadMB: c.MaxUploadMB, Confirmation: RestoreConfirmation,
		})
	}
}

type resultData struct {
	OK       bool
	Message  string
	Details  []string
	Warnings []string
}

func (m *module) respond(rt *web.Router, w http.ResponseWriter, r *http.Request, status int, res resultData) {
	if r.Header.Get("HX-Request") == "" {
		if !res.OK {
			rt.Server().Error(w, r, status, res.Message)
			return
		}
		http.Redirect(w, r, "/settings/backup", http.StatusSeeOther)
		return
	}
	rt.Server().RenderPartial(w, r, "backup/backup.html", "result", res)
}

func actorName(r *http.Request) string {
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		return p.Username
	}
	return ""
}

func (m *module) run(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev := auditlog.RequestEvent(r, "backup.run.request", "backup", audit.OutcomeSuccess)
		if !m.svc.HasPassphrase(r.Context()) {
			ev.Outcome, ev.Reason = audit.OutcomeFailure, "passphrase not configured"
			_ = rt.Server().Audit().Record(r.Context(), ev)
			m.respond(rt, w, r, http.StatusConflict, resultData{Message: ErrNoPassphrase.Error()})
			return
		}
		id, err := m.svc.jobs.Enqueue(r.Context(), JobType, runPayload{Trigger: "manual"}, actorName(r))
		if err != nil {
			ev.Outcome, ev.Reason = audit.OutcomeFailure, err.Error()
			_ = rt.Server().Audit().Record(r.Context(), ev)
			m.respond(rt, w, r, http.StatusInternalServerError, resultData{Message: "Could not start the backup job."})
			return
		}
		ev.Target = "job:" + id
		_ = rt.Server().Audit().Record(r.Context(), ev)
		if r.Header.Get("HX-Request") != "" {
			w.Header().Set("HX-Redirect", "/jobs/"+id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/jobs/"+id, http.StatusSeeOther)
	}
}

func (m *module) download(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		ev := auditlog.RequestEvent(r, "backup.download", "backup:"+name, audit.OutcomeSuccess)
		if !ValidName(name) {
			rt.Server().Error(w, r, http.StatusBadRequest, "Invalid backup name.")
			return
		}
		f, err := os.Open(filepath.Join(m.svc.cfg.Backup.Dir, name))
		if err != nil {
			rt.Server().Error(w, r, http.StatusNotFound, "Backup not found.")
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			rt.Server().Error(w, r, http.StatusNotFound, "Backup not found.")
			return
		}
		ev.Details = map[string]any{"size": fi.Size()}
		if err := rt.Server().Audit().Record(r.Context(), ev); err != nil {
			rt.Server().Error(w, r, http.StatusServiceUnavailable, "Audit log unavailable; download refused.")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, name, fi.ModTime(), f)
	}
}

func (m *module) passphrase(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			m.respond(rt, w, r, http.StatusBadRequest, resultData{Message: "Invalid form."})
			return
		}
		p, confirm := r.PostFormValue("passphrase"), r.PostFormValue("confirm")
		if p != confirm {
			m.respond(rt, w, r, http.StatusBadRequest, resultData{Message: "Passphrases do not match."})
			return
		}
		ev := auditlog.RequestEvent(r, "backup.passphrase.set", "backup:passphrase", audit.OutcomeSuccess)
		if err := m.svc.SetPassphrase(r.Context(), p); err != nil {
			ev.Outcome, ev.Reason = audit.OutcomeFailure, "rejected"
			_ = rt.Server().Audit().Record(r.Context(), ev)
			m.respond(rt, w, r, http.StatusBadRequest, resultData{Message: err.Error()})
			return
		}
		_ = rt.Server().Audit().Record(r.Context(), ev)
		m.respond(rt, w, r, http.StatusOK, resultData{OK: true,
			Message: "Backup passphrase saved (sealed). Keep a copy offline: it is required to restore."})
	}
}

// restoreForm is the parsed multipart upload.
type restoreForm struct {
	archive    string // temp file
	filename   string
	passphrase string
	confirm    string
	force      bool
}

// readRestoreForm streams the multipart body, writing the archive to a temp
// file in the backup dir.
func (m *module) readRestoreForm(w http.ResponseWriter, r *http.Request) (*restoreForm, error) {
	limit := int64(m.svc.cfg.Backup.MaxUploadMB) << 20
	r.Body = http.MaxBytesReader(w, r.Body, limit+1<<20)
	f := &restoreForm{}
	mr, err := r.MultipartReader()
	if err != nil {
		// A CSRF middleware may already have parsed the form to read
		// csrf_token; fall back to the parsed multipart form.
		if r.MultipartForm == nil {
			return nil, errors.New("expected a multipart/form-data upload")
		}
		return f, m.readParsedForm(r.MultipartForm, f, limit)
	}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return f, fmt.Errorf("read upload: %w", err)
		}
		if err := m.readPart(part, f, limit); err != nil {
			_ = part.Close()
			return f, err
		}
		_ = part.Close()
	}
	if f.archive == "" {
		return f, errors.New("choose a backup archive to upload")
	}
	return f, nil
}

func (m *module) readParsedForm(mf *multipart.Form, f *restoreForm, limit int64) error {
	first := func(k string) string {
		if v := mf.Value[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	f.passphrase, f.confirm, f.force = first("passphrase"), strings.TrimSpace(first("confirm")), first("force") == "1"
	fhs := mf.File["archive"]
	if len(fhs) != 1 {
		return errors.New("choose a backup archive to upload")
	}
	src, err := fhs[0].Open()
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll(m.svc.cfg.Backup.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.svc.cfg.Backup.Dir, ".upload-*.tmp")
	if err != nil {
		return err
	}
	f.archive, f.filename = tmp.Name(), filepath.Base(fhs[0].Filename)
	n, err := io.Copy(tmp, io.LimitReader(src, limit+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("archive exceeds the %d MB upload limit", m.svc.cfg.Backup.MaxUploadMB)
	}
	return nil
}

func (m *module) readPart(part *multipart.Part, f *restoreForm, limit int64) error {
	switch part.FormName() {
	case "archive":
		if f.archive != "" {
			return errors.New("only one archive may be uploaded")
		}
		if err := os.MkdirAll(m.svc.cfg.Backup.Dir, 0o700); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(m.svc.cfg.Backup.Dir, ".upload-*.tmp")
		if err != nil {
			return err
		}
		f.archive, f.filename = tmp.Name(), filepath.Base(part.FileName())
		n, err := io.Copy(tmp, io.LimitReader(part, limit+1))
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("read upload: %w", err)
		}
		if n > limit {
			return fmt.Errorf("archive exceeds the %d MB upload limit", m.svc.cfg.Backup.MaxUploadMB)
		}
	case "passphrase", "confirm", "force":
		b, err := io.ReadAll(io.LimitReader(part, 4096))
		if err != nil {
			return err
		}
		switch part.FormName() {
		case "passphrase":
			f.passphrase = string(b)
		case "confirm":
			f.confirm = strings.TrimSpace(string(b))
		case "force":
			f.force = string(b) == "1"
		}
	}
	return nil
}

func (m *module) restore(rt *web.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev := auditlog.RequestEvent(r, "backup.restore", "backup:upload", audit.OutcomeFailure)
		fail := func(status int, msg string) {
			ev.Reason = msg
			_ = rt.Server().Audit().Record(r.Context(), ev)
			m.respond(rt, w, r, status, resultData{Message: msg})
		}
		// Restoring needs both settings.manage (route) and backup.run.
		if p := auth.PrincipalFrom(r.Context()); p == nil ||
			rt.Server().Authorizer().Authorize(r.Context(), p, rbac.BackupRun) != nil {
			ev.Outcome = audit.OutcomeDenied
			fail(http.StatusForbidden, "missing permission "+string(rbac.BackupRun))
			return
		}
		form, err := m.readRestoreForm(w, r)
		if form != nil && form.archive != "" {
			defer os.Remove(form.archive)
		}
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		ev.Target = "backup:" + form.filename
		if form.confirm != RestoreConfirmation {
			fail(http.StatusBadRequest, "Type "+RestoreConfirmation+" to confirm the restore.")
			return
		}
		pass := []byte(form.passphrase)
		if len(pass) == 0 {
			if pass, err = m.svc.Passphrase(r.Context()); err != nil {
				fail(http.StatusBadRequest, "Enter the archive passphrase.")
				return
			}
		}
		defer clear(pass)
		res, err := m.svc.RestoreUpload(r.Context(), form.archive, pass, form.force)
		if err != nil {
			msg := err.Error()
			switch {
			case errors.Is(err, ErrWrongPassphrase):
				msg = "Wrong passphrase."
			case errors.Is(err, ErrCorrupt), errors.Is(err, ErrNotArchive):
				msg = "The archive is corrupted, tampered with or not a PerfectImage backup."
			}
			fail(http.StatusBadRequest, msg)
			return
		}
		ev.Outcome = audit.OutcomeSuccess
		ev.Details = map[string]any{
			"archive_version": res.Manifest.AppVersion, "archive_created": res.Manifest.CreatedAt,
			"restored": res.Restored, "warnings": len(res.Warnings), "forced": form.force,
		}
		if res.SafetyBackup != "" {
			ev.Details["safety_backup"] = filepath.Base(res.SafetyBackup)
		}
		_ = rt.Server().Audit().Record(r.Context(), ev)
		details := append([]string{}, res.Restored...)
		if res.SafetyBackup != "" {
			details = append(details, "safety backup: "+filepath.Base(res.SafetyBackup))
		}
		m.respond(rt, w, r, http.StatusOK, resultData{OK: true,
			Message: "Restore complete. Restart the PerfectImage service now; job processing is stopped until then.",
			Details: details, Warnings: res.Warnings})
	}
}
