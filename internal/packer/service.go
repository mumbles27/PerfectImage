package packer

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// JobType is the job type of image builds.
const JobType = "packer.build"

// Service runs packer builds. It implements jobs.Handler for JobType.
type Service struct {
	cfg     config.PackerConfig
	cat     *catalog.Store
	builds  buildStore
	sealer  secrets.Sealer
	audit   audit.Recorder
	log     *slog.Logger
	jobs    *jobs.Manager
	http    *http.Client
	creds   func() ClusterCreds
	seeds   func() SeedStore
	binary  func(ctx context.Context) (string, error)
	cleanup func(string) error
}

// Options configures NewService.
type Options struct {
	Config  config.PackerConfig
	Catalog *catalog.Store
	DB      *store.DB
	Sealer  secrets.Sealer
	Audit   audit.Recorder
	Logger  *slog.Logger
	Jobs    *jobs.Manager
	// Creds overrides the process-wide SetClusterCreds provider (tests).
	Creds ClusterCreds
	// Seeds overrides the process-wide SetSeedStore store (tests).
	Seeds SeedStore
}

// NewService returns a build service.
func NewService(o Options) *Service {
	s := &Service{
		cfg: o.Config, cat: o.Catalog, builds: buildStore{db: o.DB}, sealer: o.Sealer,
		audit: o.Audit, log: o.Logger, jobs: o.Jobs, http: &http.Client{Timeout: 10 * time.Minute},
		cleanup: os.RemoveAll,
	}
	if s.audit == nil {
		s.audit = audit.NopRecorder{}
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.creds = currentCreds
	if o.Creds != nil {
		s.creds = func() ClusterCreds { return o.Creds }
	}
	s.seeds = currentSeedStore
	if o.Seeds != nil {
		s.seeds = func() SeedStore { return o.Seeds }
	}
	s.binary = func(ctx context.Context) (string, error) { return FindBinary(ctx, s.cfg, s.http) }
	return s
}

// Submit validates a request, records the build and enqueues the job. It
// returns the build id and job id.
func (s *Service) Submit(ctx context.Context, req BuildRequest, actor string) (*Build, error) {
	c := s.cat.Catalog()
	img, steps, err := req.Check(c)
	if err != nil {
		return nil, err
	}
	req.BuildID = newBuildID()
	apps := make([]string, len(steps))
	for i, st := range steps {
		apps[i] = st.AppID
	}
	b := &Build{
		ID: req.BuildID, ImageID: img.ID, ImageName: img.Name, OSFamily: string(img.OSFamily),
		Cluster: req.Cluster, Node: req.Node, TemplateName: req.TemplateName, VMID: req.VMID,
		Request: req, Apps: apps, Status: jobs.StatusQueued, CreatedBy: actor, CreatedAt: time.Now().UTC(),
	}
	if err := s.builds.insert(ctx, b); err != nil {
		return nil, fmt.Errorf("record build: %w", err)
	}
	jobID, err := s.jobs.Enqueue(ctx, JobType, req, actor)
	if err != nil {
		_ = s.builds.finish(ctx, b.ID, jobs.StatusFailed, "", "enqueue failed", "")
		return nil, fmt.Errorf("enqueue build: %w", err)
	}
	b.JobID = jobID
	if err := s.builds.setJob(ctx, b.ID, jobID); err != nil {
		return nil, err
	}
	return b, nil
}

// Builds lists recent builds.
func (s *Service) Builds(ctx context.Context, limit int) ([]*Build, error) {
	return s.builds.list(ctx, limit)
}

// Build returns one build.
func (s *Service) Build(ctx context.Context, id string) (*Build, error) {
	return s.builds.get(ctx, id)
}

// BuildPassword returns the (unsealed) guest password of a build. The deploy
// side may need it to reach a fresh clone before resetting credentials. It
// must never be logged.
func (s *Service) BuildPassword(ctx context.Context, id string) (string, error) {
	v, err := s.builds.sealedPassword(ctx, id)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", ErrBuildNotFound
	}
	return secrets.DecryptString(s.sealer, v, "packer_build:"+id)
}

// Run implements jobs.Handler.
func (s *Service) Run(ctx context.Context, job *jobs.Job, log *jobs.LogWriter) (any, error) {
	var req BuildRequest
	if err := job.DecodePayload(&req); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if req.BuildID == "" {
		return nil, errors.New("payload has no build_id")
	}
	if s.cfg.BuildTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, s.cfg.BuildTimeout,
			fmt.Errorf("build timed out after %s", s.cfg.BuildTimeout))
		defer cancel()
	}
	start := time.Now()
	workdir := filepath.Join(s.cfg.WorkDir, "builds", req.BuildID)
	res, artifact, err := s.run(ctx, req, workdir, log)

	status := jobs.StatusSucceeded
	errMsg := ""
	switch {
	case err != nil && errors.Is(ctx.Err(), context.Canceled):
		// User cancel or service shutdown (timeouts are DeadlineExceeded).
		status, errMsg = jobs.StatusCanceled, "canceled or interrupted"
	case err != nil:
		status, errMsg = jobs.StatusFailed, err.Error()
	}
	if s.removeWorkdir(status) {
		if rmErr := s.cleanup(workdir); rmErr != nil {
			s.log.Warn("remove build workdir", "build_id", req.BuildID, "err", rmErr)
		} else {
			workdir = ""
		}
	}
	// Use a fresh context: the job context may be canceled already.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if ferr := s.builds.finish(fctx, req.BuildID, status, artifact, errMsg, workdir); ferr != nil {
		s.log.Error("record build result", "build_id", req.BuildID, "err", ferr)
	}
	ev := audit.Event{
		Actor: job.CreatedBy, Action: "image.build.finish", Target: "build:" + req.BuildID,
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"image": req.ImageID, "cluster": req.Cluster, "node": req.Node,
			"template_name": req.TemplateName, "template_id": artifact, "job_id": job.ID, "status": string(status)},
	}
	if err != nil {
		ev.Outcome, ev.Reason = audit.OutcomeFailure, errMsg
	}
	_ = s.audit.Record(fctx, ev)
	if err != nil {
		return nil, err
	}
	res.Duration = time.Since(start).Round(time.Second).String()
	return res, nil
}

func (s *Service) removeWorkdir(status jobs.Status) bool {
	switch s.cfg.KeepWorkDir {
	case "always":
		return false
	case "never":
		return true
	default: // on_failure
		return status == jobs.StatusSucceeded
	}
}

// run performs the build. It returns the result and the artifact (template
// VMID) on success.
func (s *Service) run(ctx context.Context, req BuildRequest, workdir string, log *jobs.LogWriter) (*BuildResult, string, error) {
	c := s.cat.Catalog()
	img, steps, err := req.Check(c)
	if err != nil {
		var fe FieldErrors
		if errors.As(err, &fe) {
			var parts []string
			for k, v := range fe {
				parts = append(parts, k+": "+v)
			}
			return nil, "", fmt.Errorf("invalid request: %s", strings.Join(parts, "; "))
		}
		return nil, "", err
	}
	log.Printf("==> PerfectImage build %s", req.BuildID)
	log.Printf("    image:    %s (%s)", img.Name, img.ID)
	log.Printf("    target:   cluster %s, node %s", req.Cluster, req.Node)
	log.Printf("    template: %s (vmid %s)", req.TemplateName, vmidLabel(req.VMID))
	appIDs := make([]string, len(steps))
	for i, st := range steps {
		appIDs[i] = st.AppID
	}
	if len(appIDs) > 0 {
		log.Printf("    apps:     %s", strings.Join(appIDs, ", "))
	} else {
		log.Printf("    apps:     none")
	}
	if st := req.Settings; st.Timezone != "" || st.Locale != "" || st.Keyboard != "" || st.WindowsEdition != "" {
		log.Printf("    settings: timezone=%q locale=%q keyboard=%q edition=%q", st.Timezone, st.Locale, st.Keyboard, st.WindowsEdition)
	}
	if req.Settings.Updates {
		log.Printf("    updates:  install all available OS updates")
	}
	if req.PostScript.Script != "" {
		log.Printf("    post-install script: %d bytes (reboot after: %t)", len(req.PostScript.Script), req.PostScript.Reboot)
	}

	cp := s.creds()
	if cp == nil {
		return nil, "", ErrNoCreds
	}
	endpoint, tokenID, secret, insecure, err := cp.Creds(ctx, req.Cluster)
	if err != nil {
		return nil, "", fmt.Errorf("proxmox credentials for cluster %q: %w", req.Cluster, err)
	}
	if endpoint == "" || tokenID == "" || secret == "" {
		return nil, "", fmt.Errorf("proxmox credentials for cluster %q are incomplete", req.Cluster)
	}

	password, err := randomPassword(24)
	if err != nil {
		return nil, "", err
	}
	sealed, err := secrets.EncryptString(s.sealer, password, "packer_build:"+req.BuildID)
	if err != nil {
		return nil, "", fmt.Errorf("seal build password: %w", err)
	}
	if err := os.RemoveAll(workdir); err != nil {
		return nil, "", err
	}
	if err := s.builds.start(ctx, req.BuildID, workdir, sealed, appIDs); err != nil {
		return nil, "", fmt.Errorf("record build start: %w", err)
	}

	desc := fmt.Sprintf("%s built by PerfectImage on %s (build %s)", img.Name, time.Now().UTC().Format("2006-01-02"), req.BuildID)
	if len(appIDs) > 0 {
		desc += "; apps: " + strings.Join(appIDs, ", ")
	}
	vars := Vars(img, req, insecure, desc)
	if img.Seed != nil {
		volid, cleanup, err := s.uploadSeed(ctx, img, req, password, log)
		if err != nil {
			return nil, "", err
		}
		defer cleanup()
		vars = append(vars, Var{"seed_iso_file", volid})
	}
	if err := Render(workdir, img, req.Steps(img, steps), vars); err != nil {
		return nil, "", fmt.Errorf("render workdir: %w", err)
	}
	log.Printf("==> rendered workdir %s", workdir)

	bin, err := s.binary(ctx)
	if err != nil {
		return nil, "", err
	}
	shared := s.cfg.WorkDir
	for _, d := range []string{"plugins", "cache", "config"} {
		if err := os.MkdirAll(filepath.Join(shared, d), 0o700); err != nil {
			return nil, "", err
		}
	}
	env := append(BaseEnv(),
		"PACKER_PLUGIN_PATH="+filepath.Join(shared, "plugins"),
		"PACKER_CACHE_DIR="+filepath.Join(shared, "cache"),
		"PACKER_CONFIG_DIR="+filepath.Join(shared, "config"),
		"CHECKPOINT_DISABLE=1",
		"PACKER_NO_COLOR=1",
		"PROXMOX_URL="+apiURL(endpoint),
		"PROXMOX_USERNAME="+tokenID,
		"PROXMOX_TOKEN="+secret,
		"PKR_VAR_build_password="+password,
	)
	redact := newRedactor(password, secret)
	r := Runner{Binary: bin, Dir: workdir, Env: env, Grace: s.cfg.InterruptGrace}
	raw := func(line string) { log.Printf("%s", redact(line)) }

	log.Printf("==> packer init")
	if err := r.Run(ctx, []string{"init", "."}, raw, raw); err != nil {
		return nil, "", err
	}
	log.Printf("==> packer validate")
	if err := r.Run(ctx, []string{"validate", "."}, raw, raw); err != nil {
		return nil, "", err
	}
	log.Printf("==> packer build")
	var artifact string
	onOut := func(line string) {
		ev, ok := ParseMachineLine(line)
		if !ok {
			raw(line)
			return
		}
		if id, ok := ev.ArtifactID(); ok {
			artifact = id
		}
		for _, l := range ev.Readable() {
			log.Printf("%s", redact(l))
		}
	}
	if err := r.Run(ctx, []string{"build", "-color=false", "-machine-readable", "-on-error=cleanup", "."}, onOut, raw); err != nil {
		return nil, "", err
	}
	log.Printf("==> template %s ready (vmid %s)", req.TemplateName, vmidLabel(atoiOr(artifact, req.VMID)))
	return &BuildResult{
		BuildID: req.BuildID, ImageID: img.ID, TemplateName: req.TemplateName, TemplateID: artifact,
		Cluster: req.Cluster, Node: req.Node, Apps: appIDs,
	}, artifact, nil
}

// uploadSeed renders the image's seed files, packs them into an ISO and
// uploads it to the build's ISO storage. The returned cleanup deletes the
// ISO (it contains the temporary build password) whatever the outcome,
// including cancellation.
func (s *Service) uploadSeed(ctx context.Context, img *catalog.Image, req BuildRequest, password string, log *jobs.LogWriter) (string, func(), error) {
	ss := s.seeds()
	if ss == nil {
		return "", nil, ErrNoSeedStore
	}
	files, err := RenderSeed(img, SeedData{Username: BuildUsername, Password: password})
	if err != nil {
		return "", nil, err
	}
	iso, err := SeedISO(img.Seed.Label, files)
	if err != nil {
		return "", nil, err
	}
	storage := req.ISOStorage
	if storage == "" {
		storage = "local"
	}
	name := "pi-seed-" + req.BuildID + ".iso"
	log.Printf("==> uploading seed ISO %s (label %s, %d KiB) to %s", name, img.Seed.Label, (len(iso)+1023)/1024, storage)
	volid, err := ss.PutSeed(ctx, req.Cluster, req.Node, storage, name, iso)
	if err != nil {
		return "", nil, fmt.Errorf("upload seed ISO: %w", err)
	}
	cleanup := func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if err := ss.DeleteSeed(dctx, req.Cluster, req.Node, volid); err != nil {
			log.Printf("WARNING: could not delete seed ISO %s: %v (delete it manually; it contains the temporary build password)", volid, err)
			s.log.Warn("delete seed ISO", "volid", volid, "err", err)
			return
		}
		log.Printf("==> deleted seed ISO %s", volid)
	}
	return volid, cleanup, nil
}

func vmidLabel(id int) string {
	if id == 0 {
		return "auto"
	}
	return fmt.Sprint(id)
}

func atoiOr(s string, def int) int {
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil {
		return def
	}
	return n
}

// apiURL normalizes a Proxmox endpoint to the API base URL packer expects.
func apiURL(endpoint string) string {
	e := strings.TrimRight(endpoint, "/")
	if !strings.HasSuffix(e, "/api2/json") {
		e += "/api2/json"
	}
	return e
}

// newRedactor replaces secret values in log lines.
func newRedactor(secrets ...string) func(string) string {
	var pairs []string
	for _, s := range secrets {
		if len(s) >= 4 {
			pairs = append(pairs, s, "<redacted>")
		}
	}
	r := strings.NewReplacer(pairs...)
	return r.Replace
}

const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// randomPassword returns an alphanumeric password with at least one upper,
// lower and digit (Windows complexity rules).
func randomPassword(n int) (string, error) {
	for {
		b := make([]byte, n)
		for i := range b {
			k, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordAlphabet))))
			if err != nil {
				return "", err
			}
			b[i] = passwordAlphabet[k.Int64()]
		}
		s := string(b)
		if strings.ContainsAny(s, "ABCDEFGHJKLMNPQRSTUVWXYZ") && strings.ContainsAny(s, "abcdefghijkmnopqrstuvwxyz") &&
			strings.ContainsAny(s, "23456789") {
			return s, nil
		}
	}
}
