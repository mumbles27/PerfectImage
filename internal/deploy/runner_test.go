package deploy

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

const (
	testSSHKey     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl fake@test"
	fakeAdminPW    = "Fake-Admin-Pw-123!" // obviously fake
	fakeDomainPW   = "Fake-Join-Pw-456!"
	installMarker  = "echo installing nginx"
	verifyMarker   = "systemctl is-active nginx"
	failingInstall = "exit 3"
)

func testSealer(t *testing.T) secrets.Sealer {
	t.Helper()
	s, err := secrets.NewAESGCM(bytes.Repeat([]byte{9}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var testResolver = StaticResolver{
	OSLinux: {
		"nginx": {Info: AppInfo{ID: "nginx", Name: "NGINX"}, Steps: []InstallStep{
			{Name: "nginx", Shell: ShellBash, Script: installMarker, VerifyScript: verifyMarker}}},
		"broken": {Info: AppInfo{ID: "broken", Name: "Broken"}, Steps: []InstallStep{
			{Name: "broken", Shell: ShellBash, Script: failingInstall}}},
	},
	OSWindows: {
		"7zip": {Info: AppInfo{ID: "7zip", Name: "7-Zip"}, Steps: []InstallStep{
			{Name: "7zip", Shell: ShellPowerShell, Script: "choco install 7zip -y"}}},
	},
}

type recHistory struct {
	mu     sync.Mutex
	events []string
}

func (h *recHistory) Queued(_ context.Context, id string, _ Request, _ string) error { return nil }
func (h *recHistory) Running(_ context.Context, id string, _ Request, _, node string, vmid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, "running")
	return nil
}
func (h *recHistory) Finished(_ context.Context, id, status, _ string, ips []string, cleaned bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	ev := status + ":" + strings.Join(ips, ",")
	if cleaned {
		ev += ":cleaned"
	}
	h.events = append(h.events, ev)
	return nil
}

type recAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *recAudit) Record(_ context.Context, e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func newRunner(t *testing.T, f *fakePVE) (*Runner, *recHistory, *recAudit) {
	t.Helper()
	h, a := &recHistory{}, &recAudit{}
	return &Runner{
		Clients: newFakeSource(f), Resolver: func() AppResolver { return testResolver }, Sealer: testSealer(t),
		Audit: a, History: h, PollInterval: time.Millisecond, AgentTimeout: 300 * time.Millisecond, IPWait: 10 * time.Millisecond,
	}, h, a
}

func linuxRequest() Request {
	return Request{
		RequestID: NewRequestID(), Cluster: "lab", TemplateNode: "pve1", TemplateVMID: 9000, TemplateName: "ubuntu-24.04",
		Node: "pve2", Storage: "ceph", Pool: "perfectimage", Name: "web01", Cores: 4, MemoryMB: 4096, DiskGB: 20,
		Bridge: "vmbr1", VLAN: 30, IPMode: IPStatic, IPCIDR: "10.0.10.25/24", Gateway: "10.0.10.1",
		DNSServers: []string{"10.0.0.53"}, OS: OSLinux,
		Linux: LinuxOptions{User: "ops", SSHKeys: []string{testSSHKey}}, Apps: []string{"nginx"}, CleanupOnFailure: true,
	}
}

func TestDeployLinux(t *testing.T) {
	f := newFakePVE()
	r, h, a := newRunner(t, f)
	log := &memLog{}
	res, err := r.Deploy(context.Background(), "job1", "alice", linuxRequest(), log)
	if err != nil {
		t.Fatalf("Deploy: %v\n%s", err, log)
	}
	if res.VMID != 120 || res.Node != "pve2" || strings.Join(res.IPAddresses, ",") != "10.0.10.25" {
		t.Errorf("result = %+v", res)
	}
	want := []string{"VMConfig", "NextID", "Clone", "WaitTask", "VMConfig", "SetConfig", "ResizeDisk", "WaitTask",
		"Start", "WaitTask", "AgentPing", "AgentNetworkInterfaces", "AgentExec", "AgentExecStatus", "AgentExec",
		"AgentExecStatus", "AgentNetworkInterfaces"}
	if got := f.callNames(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("calls:\n got %v\nwant %v", got, want)
	}
	if !f.has("Clone 9000->120 full=true target=pve2 storage=ceph pool=perfectimage") {
		t.Errorf("clone call wrong: %v", f.calls)
	}
	if !f.has("ResizeDisk 120 scsi0 20G") {
		t.Error("disk not resized to 20G")
	}
	p := f.setParams
	checks := map[string]string{"cores": "4", "memory": "4096", "net0": "virtio,bridge=vmbr1,tag=30", "agent": "1",
		"ciuser": "ops", "ipconfig0": "ip=10.0.10.25/24,gw=10.0.10.1", "nameserver": "10.0.0.53",
		"tags": "perfectimage-deployed;ubuntu", "ide2": "ceph:cloudinit"}
	for k, v := range checks {
		if p.Get(k) != v {
			t.Errorf("config %s = %q, want %q", k, p.Get(k), v)
		}
	}
	if p.Get("sshkeys") != proxmox.EncodeSSHKeys(testSSHKey) {
		t.Errorf("sshkeys = %q", p.Get("sshkeys"))
	}
	if len(f.execs) != 2 || strings.Join(f.execs[0].Cmd, " ") != "/bin/bash -s" || f.execs[0].Input != installMarker ||
		f.execs[1].Input != verifyMarker {
		t.Errorf("execs = %+v", f.execs)
	}
	for _, s := range []string{"Cloning template 9000 -> VM 120", "Resizing scsi0 from 10G to 20G", "Guest agent is up",
		"Installing nginx (1/1, bash)", "Verifying nginx", "succeeded"} {
		if !strings.Contains(log.String(), s) {
			t.Errorf("log missing %q:\n%s", s, log)
		}
	}
	if strings.Join(h.events, "|") != "running|succeeded:10.0.10.25" {
		t.Errorf("history = %v", h.events)
	}
	if len(a.events) != 1 || a.events[0].Action != "deploy.vm" || a.events[0].Outcome != audit.OutcomeSuccess ||
		a.events[0].Target != "vm:lab/120" || a.events[0].Actor != "alice" {
		t.Errorf("audit = %+v", a.events)
	}
}

func TestDeployWindows(t *testing.T) {
	f := newFakePVE()
	f.exitCode = func(cmd []string, input string, files map[string]string) (int, string) {
		if len(cmd) > 0 && cmd[0] == "powershell.exe" {
			script := files[cmd[len(cmd)-1]]
			if strings.Contains(script, "Add-Computer") {
				return 0, "Password set\nJoined domain corp.example.com\n" + rebootMarker + "\n"
			}
		}
		return 0, ""
	}
	r, _, _ := newRunner(t, f)
	req := Request{
		RequestID: NewRequestID(), Cluster: "lab", TemplateNode: "pve1", TemplateVMID: 9001, Name: "win01",
		IPMode: IPStatic, IPCIDR: "10.0.20.5/24", Gateway: "10.0.20.1", DNSServers: []string{"10.0.0.53"}, OS: OSWindows,
		Windows: WindowsOptions{Hostname: "WIN01", Domain: "corp.example.com", DomainUser: `CORP\svc-join`, DomainOU: "OU=Servers,DC=corp"},
		Apps:    []string{"7zip"},
	}
	var err error
	if req.Windows.AdminPassword, err = SealSecret(r.Sealer, req.RequestID, "admin_password", fakeAdminPW); err != nil {
		t.Fatal(err)
	}
	if req.Windows.DomainPassword, err = SealSecret(r.Sealer, req.RequestID, "domain_password", fakeDomainPW); err != nil {
		t.Fatal(err)
	}
	log := &memLog{}
	if _, err := r.Deploy(context.Background(), "job2", "bob", req, log); err != nil {
		t.Fatalf("Deploy: %v\n%s", err, log)
	}
	if !f.has("Reboot 120") {
		t.Error("no reboot after domain join")
	}
	var custom fakeExec
	for _, e := range f.execs {
		if e.Cmd[0] == "powershell.exe" && strings.Contains(f.files[e.Cmd[len(e.Cmd)-1]], "Add-Computer") {
			custom = e
		}
	}
	if custom.Input != fakeAdminPW+"\n"+fakeDomainPW+"\n" {
		t.Errorf("passwords not passed on stdin: %q", custom.Input)
	}
	for _, e := range f.execs {
		if strings.Contains(strings.Join(e.Cmd, " "), fakeAdminPW) || strings.Contains(strings.Join(e.Cmd, " "), fakeDomainPW) {
			t.Fatal("password in argv")
		}
	}
	for path, content := range f.files {
		if strings.Contains(content, fakeAdminPW) || strings.Contains(content, fakeDomainPW) {
			t.Fatalf("password written to guest file %s", path)
		}
		if !strings.HasPrefix(path, `C:\Windows\Temp\perfectimage-`) {
			t.Errorf("unexpected file path %s", path)
		}
	}
	if s := log.String(); strings.Contains(s, fakeAdminPW) || strings.Contains(s, fakeDomainPW) || strings.Contains(s, "pi1:") {
		t.Fatalf("job log leaks secrets:\n%s", s)
	}
	// Windows template has no cloud-init drive: no ci* params, static IP via PowerShell.
	if f.setParams.Get("ipconfig0") != "" || f.setParams.Get("cipassword") != "" {
		t.Errorf("unexpected cloud-init params: %v", f.setParams)
	}
	var script string
	for _, c := range f.files {
		if strings.Contains(c, "Add-Computer") {
			script = c
		}
	}
	for _, s := range []string{"New-NetIPAddress", "'10.0.20.5'", "PrefixLength = 24", "'CORP\\svc-join'", "OUPath = 'OU=Servers,DC=corp'", "$newName = 'WIN01'"} {
		if !strings.Contains(script, s) {
			t.Errorf("customize script missing %q:\n%s", s, script)
		}
	}
	if !strings.Contains(log.String(), "Installing 7zip (1/1, powershell)") {
		t.Errorf("log:\n%s", log)
	}
	// Each PowerShell run deletes its temp script.
	var dels int
	for _, e := range f.execs {
		if e.Cmd[0] == "cmd.exe" {
			dels++
		}
	}
	if dels != 2 {
		t.Errorf("temp script deletions = %d, want 2", dels)
	}
}

func TestDeployFailures(t *testing.T) {
	tests := []struct {
		name        string
		mut         func(*Request, *fakePVE)
		wantErr     string
		wantCalls   []string // prefixes that must appear
		wantNoCalls []string
		wantHistory string
	}{
		{
			name:        "install fails with cleanup",
			mut:         func(r *Request, f *fakePVE) { r.Apps = []string{"broken"} },
			wantErr:     "exited with code 3",
			wantCalls:   []string{"Stop 120", "DeleteVM 120"},
			wantHistory: "failed:10.0.10.25:cleaned",
		},
		{
			name:        "install fails without cleanup",
			mut:         func(r *Request, f *fakePVE) { r.Apps = []string{"broken"}; r.CleanupOnFailure = false },
			wantErr:     "exited with code 3",
			wantNoCalls: []string{"DeleteVM"},
			wantHistory: "failed:10.0.10.25",
		},
		{
			name:        "post-deploy script fails with cleanup",
			mut:         func(r *Request, f *fakePVE) { r.PostScript = "exit 3" },
			wantErr:     "post-deploy script exited with code 3",
			wantCalls:   []string{"Stop 120", "DeleteVM 120"},
			wantHistory: "failed:10.0.10.25:cleaned",
		},
		{
			name:        "unknown app fails before clone",
			mut:         func(r *Request, f *fakePVE) { r.Apps = []string{"nope"} },
			wantErr:     "unknown app",
			wantNoCalls: []string{"Clone", "DeleteVM"},
			wantHistory: "failed:",
		},
		{
			name:        "agent never comes up",
			mut:         func(r *Request, f *fakePVE) { f.readyPing = 0 },
			wantErr:     "guest agent did not answer",
			wantCalls:   []string{"DeleteVM 120"},
			wantHistory: "failed::cleaned",
		},
		{
			name:        "not a template",
			mut:         func(r *Request, f *fakePVE) { r.TemplateVMID = 500 },
			wantErr:     "not a template",
			wantNoCalls: []string{"Clone"},
			wantHistory: "failed:",
		},
		{
			name:        "OS mismatch",
			mut:         func(r *Request, f *fakePVE) { r.TemplateVMID = 9001 },
			wantErr:     "windows template",
			wantNoCalls: []string{"Clone"},
			wantHistory: "failed:",
		},
		{
			name: "clone forbidden",
			mut: func(r *Request, f *fakePVE) {
				f.failOn["Clone"] = &proxmox.APIError{StatusCode: 403, Message: "Permission check failed"}
			},
			wantErr:     "Permission check failed",
			wantNoCalls: []string{"DeleteVM"},
			wantHistory: "failed:",
		},
		{
			name:        "configure fails, VM cleaned up",
			mut:         func(r *Request, f *fakePVE) { f.failOn["SetConfig"] = errBoom },
			wantErr:     "configure: boom",
			wantCalls:   []string{"DeleteVM 120"},
			wantNoCalls: []string{"Stop"},
			wantHistory: "failed::cleaned",
		},
		{
			name:        "invalid request",
			mut:         func(r *Request, f *fakePVE) { r.Name = "bad name!" },
			wantErr:     "invalid request",
			wantNoCalls: []string{"VMConfig"},
			wantHistory: "failed:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakePVE()
			r, h, a := newRunner(t, f)
			req := linuxRequest()
			tt.mut(&req, f)
			log := &memLog{}
			_, err := r.Deploy(context.Background(), "job", "alice", req, log)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q\n%s", err, tt.wantErr, log)
			}
			for _, c := range tt.wantCalls {
				if !f.has(c) {
					t.Errorf("missing call %q in %v", c, f.calls)
				}
			}
			for _, c := range tt.wantNoCalls {
				if f.has(c) {
					t.Errorf("unexpected call %q", c)
				}
			}
			if got := h.events[len(h.events)-1]; got != tt.wantHistory {
				t.Errorf("history = %q, want %q", got, tt.wantHistory)
			}
			if len(a.events) != 1 || a.events[0].Outcome != audit.OutcomeFailure {
				t.Errorf("audit = %+v", a.events)
			}
		})
	}
}

func TestDeployCanceled(t *testing.T) {
	f := newFakePVE()
	f.readyPing = 0
	r, _, _ := newRunner(t, f)
	r.AgentTimeout = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := r.Deploy(ctx, "job", "alice", linuxRequest(), &memLog{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if !f.has("DeleteVM 120") {
		t.Error("canceled deploy not cleaned up")
	}
}

func TestRequestValidate(t *testing.T) {
	sealed := "pi1:sealed"
	tests := []struct {
		name    string
		mut     func(*Request)
		wantErr string
	}{
		{"valid linux", func(*Request) {}, ""},
		{"valid dhcp", func(r *Request) { r.IPMode, r.IPCIDR, r.Gateway = IPDHCP, "", "" }, ""},
		{"valid ipv6", func(r *Request) { r.IPCIDR, r.Gateway = "2001:db8::10/64", "2001:db8::1" }, ""},
		{"missing cluster", func(r *Request) { r.Cluster = "" }, "choose a cluster"},
		{"bad name", func(r *Request) { r.Name = "-web" }, "valid DNS name"},
		{"low vmid", func(r *Request) { r.VMID = 5 }, "VMID"},
		{"vlan without bridge", func(r *Request) { r.Bridge = "" }, "needs a bridge"},
		{"vlan range", func(r *Request) { r.VLAN = 5000 }, "VLAN"},
		{"bad cidr", func(r *Request) { r.IPCIDR = "10.0.0.5" }, "CIDR"},
		{"gateway outside", func(r *Request) { r.Gateway = "192.168.1.1" }, "outside"},
		{"static fields with dhcp", func(r *Request) { r.IPMode = IPDHCP }, "only used with a static IP"},
		{"bad dns", func(r *Request) { r.DNSServers = []string{"dns.example"} }, "DNS server"},
		{"root user", func(r *Request) { r.Linux.User = "root" }, "cloud-init user"},
		{"bad ssh key", func(r *Request) { r.Linux.SSHKeys = []string{"ssh-ed25519 notbase64!"} }, "SSH public key"},
		{"mismatched ssh key type", func(r *Request) { r.Linux.SSHKeys = []string{strings.Replace(testSSHKey, "ssh-ed25519", "ssh-rsa", 1)} }, "SSH public key"},
		{"keys without user", func(r *Request) { r.Linux.User = "" }, "need a cloud-init user"},
		{"bad storage", func(r *Request) { r.Storage = "a b" }, "invalid storage"},
		{"bad app id", func(r *Request) { r.Apps = []string{"../x"} }, "invalid app id"},
		{"post script too big", func(r *Request) { r.PostScript = strings.Repeat("x", maxScriptBytes+1) }, "post-deploy script is larger"},
		{"post script binary", func(r *Request) { r.PostScript = "echo\x00" }, "post-deploy script must be UTF-8"},
		{"windows ok", func(r *Request) {
			r.OS, r.Linux = OSWindows, LinuxOptions{}
			r.Windows = WindowsOptions{Hostname: "WEB01", Domain: "corp.example.com", DomainUser: "joiner@corp.example.com", DomainPassword: sealed}
		}, ""},
		{"windows long hostname", func(r *Request) {
			r.OS, r.Linux = OSWindows, LinuxOptions{}
			r.Windows.Hostname = "THIS-NAME-IS-TOO-LONG"
		}, "1-15"},
		{"domain without password", func(r *Request) {
			r.OS, r.Linux = OSWindows, LinuxOptions{}
			r.Windows = WindowsOptions{Domain: "corp.example.com", DomainUser: "joiner"}
		}, "needs a password"},
		{"domain user without domain", func(r *Request) {
			r.OS, r.Linux = OSWindows, LinuxOptions{}
			r.Windows = WindowsOptions{DomainUser: "joiner"}
		}, "need a domain"},
		{"unknown os", func(r *Request) { r.OS = "bsd" }, "unknown OS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := linuxRequest()
			tt.mut(&r)
			err := r.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestPSQuoteAndMetadata(t *testing.T) {
	if got := psQuote("O'Brien\u2019s"); got != "'O''Brien\u2019\u2019s'" {
		t.Errorf("psQuote = %s", got)
	}
	md := ParseBuildMetadata("Built by PerfectImage\n- build_id: b-1\nimage=ubuntu\nnot a pair\nurl: https://x/y")
	if len(md) != 3 || md[0] != [2]string{"build_id", "b-1"} || md[1] != [2]string{"image", "ubuntu"} || md[2][1] != "https://x/y" {
		t.Errorf("metadata = %v", md)
	}
}

func TestResolverSeam(t *testing.T) {
	t.Cleanup(func() { SetAppResolver(nil) })
	if _, err := CurrentAppResolver().Resolve(context.Background(), OSLinux, []string{"x"}); !errors.Is(err, ErrUnknownApp) {
		t.Fatalf("stub err = %v", err)
	}
	SetAppResolver(testResolver)
	steps, err := CurrentAppResolver().Resolve(context.Background(), OSLinux, []string{"nginx"})
	if err != nil || len(steps) != 1 || steps[0].VerifyScript != verifyMarker {
		t.Fatalf("steps = %+v, %v", steps, err)
	}
	apps, _ := CurrentAppResolver().(AppLister).Apps(context.Background(), OSLinux)
	if len(apps) != 2 || apps[0].Name != "Broken" {
		t.Errorf("apps = %+v", apps)
	}
}

// TestDeployJob runs deploy.vm through the real job manager and history store.
func TestDeployJob(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "pi.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	f := newFakePVE()
	r, _, _ := newRunner(t, f)
	hist := NewHistoryStore(db)
	r.History = hist
	mgr := jobs.New(db, jobs.Options{Workers: 1, PollInterval: 10 * time.Millisecond})
	if err := mgr.Register(JobType, r); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Stop(c)
	})
	req := linuxRequest()
	id, err := mgr.Enqueue(ctx, JobType, req, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := hist.Queued(ctx, id, req, "alice"); err != nil {
		t.Fatal(err)
	}
	var j *jobs.Job
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if j, err = mgr.Get(ctx, id); err == nil && j.Status.Terminal() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if j == nil || j.Status != jobs.StatusSucceeded {
		t.Fatalf("job = %+v", j)
	}
	if !strings.Contains(string(j.Result), `"vmid":120`) {
		t.Errorf("result = %s", j.Result)
	}
	lines, _ := mgr.Logs(ctx, id, 0, 500)
	var all []string
	for _, l := range lines {
		all = append(all, l.Line)
	}
	if !strings.Contains(strings.Join(all, "\n"), "Installing nginx") {
		t.Errorf("job log:\n%s", strings.Join(all, "\n"))
	}
	list, err := hist.List(ctx, 10)
	if err != nil || len(list) != 1 || list[0].Status != StatusSucceeded || list[0].VMID != 120 ||
		list[0].IPAddresses != "10.0.10.25" || list[0].FinishedAt == nil || list[0].Apps[0] != "nginx" {
		t.Fatalf("history = %+v, %v", list, err)
	}
}

func TestDeployPostScript(t *testing.T) {
	f := newFakePVE()
	r, _, _ := newRunner(t, f)
	log := &memLog{}
	req := linuxRequest()
	req.PostScript = "systemctl enable --now nginx\n"
	if _, err := r.Deploy(context.Background(), "job1", "alice", req, log); err != nil {
		t.Fatalf("Deploy: %v\n%s", err, log)
	}
	// install, verify, then the post-deploy script (after the apps).
	if len(f.execs) != 3 || strings.Join(f.execs[2].Cmd, " ") != "/bin/bash -s" || f.execs[2].Input != req.PostScript {
		t.Fatalf("execs = %+v", f.execs)
	}
	if !strings.Contains(log.String(), "[8] Running the post-deploy script") {
		t.Fatalf("log:\n%s", log)
	}
}
