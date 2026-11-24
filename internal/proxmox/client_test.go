package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTokenID = "perfectimage@pve!test"
	testSecret  = "00000000-1111-2222-3333-444444444444" // obviously fake
)

// fakePVE is a minimal in-memory Proxmox VE API.
type fakePVE struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	vms      map[int]map[string]any // vmid -> config
	status   map[int]string
	tasks    map[string]int // upid -> remaining "running" polls
	taskExit map[string]string
	nextID   int
	requests []string
	forms    map[string]url.Values // "METHOD path" -> last form
	gets     atomic.Int32
	failGets int32 // first N GETs of /version answer 503
}

func newFakePVE(t *testing.T) *fakePVE {
	t.Helper()
	f := &fakePVE{
		t:        t,
		vms:      map[int]map[string]any{9000: {"name": "ubuntu-tpl", "template": 1, "ostype": "l26", "scsi0": "local-lvm:base-9000-disk-0,size=10G", "ide2": "local-lvm:vm-9000-cloudinit,media=cdrom", "boot": "order=scsi0", "tags": "perfectimage;ubuntu"}},
		status:   map[int]string{9000: "stopped"},
		tasks:    map[string]int{},
		taskExit: map[string]string{},
		nextID:   100,
		forms:    map[string]url.Values{},
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePVE) fingerprint() string {
	sum := sha256.Sum256(f.srv.Certificate().Raw)
	return FormatFingerprint(sum[:])
}

func (f *fakePVE) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func (f *fakePVE) client(t *testing.T, mut func(*Options)) *Client {
	t.Helper()
	o := Options{Endpoint: f.srv.URL, TokenID: testTokenID, Secret: testSecret, CAPEM: f.caPEM(),
		RetryBaseDelay: time.Millisecond, TaskPollInterval: time.Millisecond}
	if mut != nil {
		mut(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakePVE) newTask(node, typ string, vmid, polls int, exit string) string {
	upid := fmt.Sprintf("UPID:%s:0000ABCD:00001234:%08X:%s:%d:%s:", node, len(f.tasks)+1, typ, vmid, testTokenID)
	f.tasks[upid] = polls
	f.taskExit[upid] = exit
	return upid
}

func writeData(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
}

func pveError(w http.ResponseWriter, code int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	// PVE puts the message in the reason phrase; Go cannot set a custom
	// one, so the body carries it like newer PVE versions do.
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": reason})
}

func (f *fakePVE) serve(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "PVEAPIToken="+testTokenID+"="+testSecret {
		pveError(w, http.StatusUnauthorized, "authentication failure")
		return
	}
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api2/json")
	f.requests = append(f.requests, r.Method+" "+path)
	f.forms[r.Method+" "+path] = r.PostForm
	parts := strings.Split(strings.Trim(path, "/"), "/")

	switch {
	case path == "/version":
		if r.Method == http.MethodGet && f.gets.Add(1) <= f.failGets {
			pveError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
		writeData(w, map[string]any{"version": "8.3.2", "release": "8.3", "repoid": "deadbeef"})
	case path == "/nodes":
		writeData(w, []map[string]any{{"node": "pve1", "status": "online", "maxcpu": 16}})
	case path == "/forbidden":
		pveError(w, http.StatusForbidden, "Permission check failed (/vms/100, VM.Allocate)")
	case path == "/badparam":
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "errors": map[string]string{"memory": "value must be >= 16"}})
	case path == "/cluster/nextid":
		writeData(w, fmt.Sprint(f.nextID))
	case path == "/cluster/resources":
		var out []map[string]any
		for id, cfg := range f.vms {
			out = append(out, map[string]any{"id": fmt.Sprintf("qemu/%d", id), "type": "qemu", "node": "pve1",
				"vmid": id, "name": cfg["name"], "template": cfg["template"], "tags": cfg["tags"]})
		}
		writeData(w, out)
	case len(parts) == 5 && parts[0] == "nodes" && parts[2] == "tasks" && parts[4] == "status":
		upid, _ := url.PathUnescape(parts[3])
		n, ok := f.tasks[upid]
		if !ok {
			pveError(w, http.StatusInternalServerError, "no such task")
			return
		}
		if n > 0 {
			f.tasks[upid] = n - 1
			writeData(w, map[string]any{"upid": upid, "status": "running", "node": parts[1]})
			return
		}
		writeData(w, map[string]any{"upid": upid, "status": "stopped", "exitstatus": f.taskExit[upid], "node": parts[1]})
	case len(parts) >= 4 && parts[0] == "nodes" && parts[2] == "qemu":
		f.serveVM(w, r, parts)
	default:
		pveError(w, http.StatusNotImplemented, "Method '"+r.Method+" "+path+"' not implemented")
	}
}

func (f *fakePVE) serveVM(w http.ResponseWriter, r *http.Request, parts []string) {
	node := parts[1]
	var vmid int
	fmt.Sscan(parts[3], &vmid)
	cfg, ok := f.vms[vmid]
	if !ok {
		pveError(w, http.StatusInternalServerError, fmt.Sprintf("Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist", node, vmid))
		return
	}
	action := strings.Join(parts[4:], "/")
	switch {
	case r.Method == http.MethodGet && action == "config":
		writeData(w, cfg)
	case r.Method == http.MethodPost && action == "clone":
		var newID int
		fmt.Sscan(r.PostForm.Get("newid"), &newID)
		if _, exists := f.vms[newID]; exists {
			pveError(w, http.StatusInternalServerError, "unable to create VM: config file already exists")
			return
		}
		nc := map[string]any{}
		for k, v := range cfg {
			nc[k] = v
		}
		delete(nc, "template")
		nc["name"] = r.PostForm.Get("name")
		f.vms[newID] = nc
		f.status[newID] = "stopped"
		f.nextID = newID + 1
		writeData(w, f.newTask(node, "qmclone", vmid, 2, "OK"))
	case r.Method == http.MethodPost && action == "config":
		for k := range r.PostForm {
			cfg[k] = r.PostForm.Get(k)
		}
		writeData(w, nil)
	case r.Method == http.MethodPost && action == "status/start":
		f.status[vmid] = "running"
		writeData(w, f.newTask(node, "qmstart", vmid, 1, "OK"))
	case r.Method == http.MethodGet && action == "status/current":
		writeData(w, map[string]any{"vmid": vmid, "status": f.status[vmid], "agent": 1})
	case r.Method == http.MethodDelete && action == "":
		delete(f.vms, vmid)
		writeData(w, f.newTask(node, "qmdestroy", vmid, 0, "OK"))
	case r.Method == http.MethodPost && action == "template":
		writeData(w, f.newTask(node, "qmtemplate", vmid, 0, "command 'qm template' failed: exit code 1"))
	case r.Method == http.MethodPost && action == "agent/exec":
		writeData(w, map[string]any{"pid": 4242})
	case r.Method == http.MethodGet && action == "agent/exec-status":
		writeData(w, map[string]any{"exited": 1, "exitcode": 0, "out-data": "hello\n"})
	default:
		pveError(w, http.StatusNotImplemented, "not implemented: "+action)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"https://pve.example.com:8006/api2/json", "https://pve.example.com:8006/api2/json", false},
		{"https://pve.example.com", "https://pve.example.com:8006/api2/json", false},
		{"pve.example.com:443/", "https://pve.example.com:443/api2/json", false},
		{"https://[2001:db8::1]/api2/json/", "https://[2001:db8::1]:8006/api2/json", false},
		{"http://pve.example.com", "", true},
		{"https://pve.example.com/other", "", true},
		{"https://user:pw@pve.example.com", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeEndpoint(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("NormalizeEndpoint(%q) = %q, %v; want %q, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		o    Options
	}{
		{"bad token id", Options{Endpoint: "https://pve", TokenID: "root", Secret: testSecret}},
		{"empty secret", Options{Endpoint: "https://pve", TokenID: testTokenID}},
		{"newline secret", Options{Endpoint: "https://pve", TokenID: testTokenID, Secret: "a\nb"}},
		{"bad fingerprint", Options{Endpoint: "https://pve", TokenID: testTokenID, Secret: testSecret, Fingerprint: "abc"}},
		{"bad CA", Options{Endpoint: "https://pve", TokenID: testTokenID, Secret: testSecret, CAPEM: []byte("nope")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.o); err == nil {
				t.Fatal("expected error")
			} else if strings.Contains(err.Error(), testSecret) {
				t.Fatal("error leaks secret")
			}
		})
	}
}

func TestAuthHeader(t *testing.T) {
	f := newFakePVE(t)
	ctx := context.Background()
	v, err := f.client(t, nil).Version(ctx)
	if err != nil || v.Version != "8.3.2" {
		t.Fatalf("Version = %+v, %v", v, err)
	}
	bad := f.client(t, func(o *Options) { o.Secret = "ffffffff-0000-0000-0000-000000000000" })
	_, err = bad.Version(ctx)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if strings.Contains(err.Error(), "ffffffff") {
		t.Fatal("error leaks secret")
	}
}

func TestTLSVerification(t *testing.T) {
	f := newFakePVE(t)
	otherFP := strings.Repeat("AB:", 31) + "AB"
	tests := []struct {
		name    string
		mut     func(*Options)
		wantErr error // nil: success; errAny: any error
	}{
		{"pinned CA", nil, nil},
		{"system roots reject self-signed", func(o *Options) { o.CAPEM = nil }, errAny},
		{"fingerprint match", func(o *Options) { o.CAPEM = nil; o.Fingerprint = f.fingerprint() }, nil},
		{"fingerprint match lowercase no colons", func(o *Options) {
			o.CAPEM = nil
			o.Fingerprint = strings.ToLower(strings.ReplaceAll(f.fingerprint(), ":", ""))
		}, nil},
		{"fingerprint mismatch", func(o *Options) { o.CAPEM = nil; o.Fingerprint = otherFP }, ErrTLSPin},
		{"fingerprint mismatch beats insecure", func(o *Options) {
			o.CAPEM = nil
			o.Fingerprint = otherFP
			o.InsecureSkipVerify = true
		}, ErrTLSPin},
		{"fingerprint + CA", func(o *Options) { o.Fingerprint = f.fingerprint() }, nil},
		{"insecure", func(o *Options) { o.CAPEM = nil; o.InsecureSkipVerify = true }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := f.client(t, func(o *Options) {
				o.Retries = -1
				if tt.mut != nil {
					tt.mut(o)
				}
			})
			_, err := c.Version(context.Background())
			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr == errAny && err == nil:
				t.Fatal("expected error")
			case tt.wantErr != nil && tt.wantErr != errAny && !errors.Is(err, tt.wantErr):
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

var errAny = errors.New("any error")

func TestErrorMapping(t *testing.T) {
	f := newFakePVE(t)
	c := f.client(t, func(o *Options) { o.Retries = -1 })
	ctx := context.Background()
	tests := []struct {
		name string
		call func() error
		want error
		not  error
	}{
		{"missing VM is ErrNotFound", func() error { _, err := c.VMConfig(ctx, "pve1", 555); return err }, ErrNotFound, ErrServer},
		{"403", func() error { return c.get(ctx, "/forbidden", nil, nil) }, ErrForbidden, nil},
		{"400 param errors", func() error { return c.get(ctx, "/badparam", nil, nil) }, ErrBadRequest, nil},
		{"501 server", func() error { return c.get(ctx, "/nope", nil, nil) }, ErrServer, ErrNotFound},
		{"task failure", func() error {
			upid, err := c.ConvertToTemplate(ctx, "pve1", 9000)
			if err != nil {
				return err
			}
			_, err = c.WaitTask(ctx, upid)
			var te *TaskError
			if !errors.As(err, &te) || te.Type != "qmtemplate" {
				t.Errorf("want TaskError, got %v", err)
			}
			return err
		}, nil, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if tt.not != nil && errors.Is(err, tt.not) {
				t.Errorf("err = %v must not match %v", err, tt.not)
			}
		})
	}
	var ae *APIError
	err := c.get(ctx, "/badparam", nil, nil)
	if !errors.As(err, &ae) || ae.Errors["memory"] == "" || !strings.Contains(err.Error(), "memory: value must be >= 16") {
		t.Errorf("APIError = %#v", ae)
	}
}

func TestGETRetries(t *testing.T) {
	f := newFakePVE(t)
	f.failGets = 2
	c := f.client(t, nil)
	if _, err := c.Version(context.Background()); err != nil {
		t.Fatalf("Version after 2 transient failures: %v", err)
	}
	if got := f.gets.Load(); got != 3 {
		t.Errorf("GET attempts = %d, want 3", got)
	}

	f.gets.Store(0)
	f.failGets = 10
	c = f.client(t, func(o *Options) { o.Retries = 1 })
	if _, err := c.Version(context.Background()); err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if got := f.gets.Load(); got != 2 {
		t.Errorf("GET attempts = %d, want 2", got)
	}
}

func TestPOSTNotRetried(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		pveError(w, http.StatusServiceUnavailable, "busy")
	}))
	defer srv.Close()
	c, err := New(Options{Endpoint: srv.URL, TokenID: testTokenID, Secret: testSecret, Transport: srv.Client().Transport,
		RetryBaseDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Start(context.Background(), "pve1", 100); err == nil {
		t.Fatal("expected error")
	}
	if n.Load() != 1 {
		t.Fatalf("POST attempts = %d, want 1", n.Load())
	}
}

func TestNoRedirect(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api2/json/version", http.StatusFound)
	}))
	defer srv.Close()
	c, _ := New(Options{Endpoint: srv.URL, TokenID: testTokenID, Secret: testSecret, Transport: srv.Client().Transport, Retries: -1})
	if _, err := c.Version(context.Background()); err == nil {
		t.Error("expected error for redirect")
	}
	if leaked.Load() {
		t.Fatal("token sent to redirect target")
	}
}

func TestCloneFlow(t *testing.T) {
	f := newFakePVE(t)
	c := f.client(t, nil)
	ctx := context.Background()

	tpls, err := c.Templates(ctx)
	if err != nil || len(tpls) != 1 || tpls[0].VMID != 9000 || !contains(tpls[0].TagList(), "perfectimage") {
		t.Fatalf("Templates = %+v, %v", tpls, err)
	}
	id, err := c.NextID(ctx)
	if err != nil || id != 100 {
		t.Fatalf("NextID = %d, %v", id, err)
	}
	upid, err := c.Clone(ctx, "pve1", 9000, CloneOptions{NewID: id, Name: "web01", Full: true, Storage: "local-lvm", Pool: "pi", Target: "pve1"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.WaitTask(ctx, upid)
	if err != nil || !st.OK() {
		t.Fatalf("WaitTask = %+v, %v", st, err)
	}
	f.mu.Lock()
	form := f.forms["POST /nodes/pve1/qemu/9000/clone"]
	f.mu.Unlock()
	want := url.Values{"newid": {"100"}, "name": {"web01"}, "full": {"1"}, "storage": {"local-lvm"}, "pool": {"pi"}, "target": {"pve1"}}
	for k, v := range want {
		if form.Get(k) != v[0] {
			t.Errorf("clone form %s = %q, want %q", k, form.Get(k), v[0])
		}
	}

	params := url.Values{"cores": {"4"}, "memory": {"4096"}}
	CloudInit{User: "ops", SSHKeys: []string{"ssh-ed25519 AAAAC3Nza fake@test"}, IPConfig: map[int]string{0: "ip=dhcp"}}.Apply(params)
	if _, err := c.SetConfig(ctx, "pve1", 100, params); err != nil {
		t.Fatal(err)
	}
	cfg, err := c.VMConfig(ctx, "pve1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Get("ciuser") != "ops" || cfg.Get("ipconfig0") != "ip=dhcp" || cfg.Get("cores") != "4" {
		t.Errorf("config = %v", cfg)
	}
	if got, _ := url.QueryUnescape(cfg.Get("sshkeys")); got != "ssh-ed25519 AAAAC3Nza fake@test" {
		t.Errorf("sshkeys round trip = %q (raw %q)", got, cfg.Get("sshkeys"))
	}
	if cfg.BootDisk() != "scsi0" || cfg.DiskSizeBytes("scsi0") != 10<<30 || !cfg.HasCloudInit() || cfg.IsTemplate() {
		t.Errorf("config helpers: boot=%s size=%d ci=%v tpl=%v", cfg.BootDisk(), cfg.DiskSizeBytes("scsi0"), cfg.HasCloudInit(), cfg.IsTemplate())
	}

	if upid, err = c.Start(ctx, "pve1", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WaitTask(ctx, upid); err != nil {
		t.Fatal(err)
	}
	vs, err := c.VMStatus(ctx, "pve1", 100)
	if err != nil || vs.Status != "running" {
		t.Fatalf("status = %+v, %v", vs, err)
	}
	pid, err := c.AgentExec(ctx, "pve1", 100, []string{"/bin/bash", "-s"}, "echo hello")
	if err != nil || pid != 4242 {
		t.Fatalf("AgentExec = %d, %v", pid, err)
	}
	es, err := c.AgentExecStatus(ctx, "pve1", 100, pid)
	if err != nil || !bool(es.Exited) || es.OutData != "hello\n" {
		t.Fatalf("exec status = %+v, %v", es, err)
	}
	if upid, err = c.DeleteVM(ctx, "pve1", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WaitTask(ctx, upid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VMConfig(ctx, "pve1", 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete err = %v", err)
	}
}

func TestWaitTaskContext(t *testing.T) {
	f := newFakePVE(t)
	c := f.client(t, nil)
	f.mu.Lock()
	upid := f.newTask("pve1", "qmclone", 1, 1<<30, "OK")
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.WaitTask(ctx, upid); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.WaitTask(ctx, "garbage"); err == nil {
		t.Fatal("expected UPID parse error")
	}
}

func TestUploadISO(t *testing.T) {
	var got struct {
		content, filename, body string
		fieldOrder              []string
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mr, err := r.MultipartReader(); err == nil {
			// Record the part order (PVE parses the stream in order).
			got.fieldOrder = nil
			for {
				p, err := mr.NextPart()
				if err != nil {
					break
				}
				got.fieldOrder = append(got.fieldOrder, p.FormName())
				b, _ := io.ReadAll(p)
				switch p.FormName() {
				case "content":
					got.content = string(b)
				case "filename":
					got.filename, got.body = p.FileName(), string(b)
				}
			}
			if r.ContentLength <= 0 || len(r.TransferEncoding) > 0 {
				t.Errorf("upload must have a Content-Length (te=%v len=%d)", r.TransferEncoding, r.ContentLength)
			}
			if got.filename == "" {
				http.Error(w, "incomplete body", http.StatusBadRequest)
				return
			}
			writeData(w, "UPID:pve1:00000001:00000001:00000001:imgcopy::root@pam:")
			return
		}
		http.Error(w, "not multipart", http.StatusBadRequest)
	}))
	defer srv.Close()
	c, _ := New(Options{Endpoint: srv.URL, TokenID: testTokenID, Secret: testSecret, Transport: srv.Client().Transport})
	upid, err := c.UploadISO(context.Background(), "pve1", "local", "test.iso", strings.NewReader("ISO DATA"), UploadOptions{})
	if err != nil || !strings.HasPrefix(upid, "UPID:pve1") {
		t.Fatalf("UploadISO = %q, %v", upid, err)
	}
	if got.content != "iso" || got.filename != "test.iso" || got.body != "ISO DATA" {
		t.Errorf("upload = %+v", got)
	}
	// PVE requires checksum-algorithm before checksum, all before the file.
	if _, err := c.UploadISO(context.Background(), "pve1", "local", "c.iso", strings.NewReader("X"),
		UploadOptions{Checksum: "ab", ChecksumAlgorithm: "sha256"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.fieldOrder, ",") != "content,checksum-algorithm,checksum,filename" {
		t.Errorf("multipart field order = %v", got.fieldOrder)
	}
	if _, err := c.UploadISO(context.Background(), "pve1", "local", "../x.iso", strings.NewReader(""), UploadOptions{}); err == nil {
		t.Error("expected filename validation error")
	}
	// Unknown size is rejected up front; an explicit Size streams any reader.
	if _, err := c.UploadISO(context.Background(), "pve1", "local", "p.iso", io.MultiReader(strings.NewReader("x")), UploadOptions{}); err == nil {
		t.Error("expected unknown-size error")
	}
	if _, err := c.UploadISO(context.Background(), "pve1", "local", "p.iso", io.MultiReader(strings.NewReader("PIPED")), UploadOptions{Size: 5}); err != nil || got.body != "PIPED" {
		t.Errorf("sized upload = %q, %v", got.body, err)
	}
	// A source shorter than the declared size fails instead of hanging.
	if _, err := c.UploadISO(context.Background(), "pve1", "local", "p.iso", io.MultiReader(strings.NewReader("AB")), UploadOptions{Size: 5}); err == nil {
		t.Error("expected short-read error")
	}
	// Files: size from Stat.
	fp := filepath.Join(t.TempDir(), "f.iso")
	if err := os.WriteFile(fp, []byte("FROM FILE"), 0o600); err != nil {
		t.Fatal(err)
	}
	fh, _ := os.Open(fp)
	defer fh.Close()
	if _, err := c.UploadISO(context.Background(), "pve1", "local", "f.iso", fh, UploadOptions{}); err != nil || got.body != "FROM FILE" {
		t.Errorf("file upload = %q, %v", got.body, err)
	}
}

func TestParseHelpers(t *testing.T) {
	u, err := ParseUPID("UPID:pve2:003B4C1A:0E6F0A3B:65F1A2B3:qmclone:9000:perfectimage@pve!deploy:")
	if err != nil || u.Node != "pve2" || u.Type != "qmclone" || u.ID != "9000" {
		t.Fatalf("ParseUPID = %+v, %v", u, err)
	}
	sizes := map[string]int64{"10G": 10 << 30, "512M": 512 << 20, "1T": 1 << 40, "1024": 1024, "1.5G": 3 << 29}
	for in, want := range sizes {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v", in, got, err)
		}
	}
	var r []Resource
	if err := json.Unmarshal([]byte(`[{"vmid":"101","template":"1","maxmem":2147483648},{"vmid":102,"template":0}]`), &r); err != nil {
		t.Fatal(err)
	}
	if r[0].VMID != 101 || !bool(r[0].Template) || bool(r[1].Template) {
		t.Errorf("flex decode = %+v", r)
	}
	if got := EncodeSSHKeys("ssh-rsa AAA+/= a@b"); got != "ssh-rsa%20AAA%2B%2F%3D%20a%40b" {
		t.Errorf("EncodeSSHKeys = %q", got)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
