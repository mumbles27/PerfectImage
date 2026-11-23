package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/jobs"
	"github.com/mumbles27/PerfectImage/internal/proxmox"
	"github.com/mumbles27/PerfectImage/internal/secrets"
)

// Tags set on deployed VMs.
const (
	TagTemplate = "perfectimage"
	TagDeployed = "perfectimage-deployed"
)

// maxScriptBytes is the largest script the guest agent accepts (PVE caps
// input-data and file-write content at ~60 KiB).
const maxScriptBytes = 60000

// Logger receives job log lines. *jobs.LogWriter implements it. Never pass
// secrets.
type Logger interface {
	Printf(format string, a ...any)
}

// Result is the deploy.vm job result.
type Result struct {
	Cluster     string   `json:"cluster"`
	Node        string   `json:"node"`
	VMID        int      `json:"vmid"`
	Name        string   `json:"name"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	Apps        []string `json:"apps,omitempty"`
}

// Runner executes deploy.vm jobs.
type Runner struct {
	Clients ClientSource
	// Resolver returns the app resolver (default CurrentAppResolver).
	Resolver func() AppResolver
	Sealer   secrets.Sealer
	Audit    audit.Recorder
	History  History
	Log      *slog.Logger

	// TaskTimeout bounds each PVE task; AgentTimeout bounds waiting for the
	// guest agent; ExecTimeout bounds each guest script.
	TaskTimeout  time.Duration
	AgentTimeout time.Duration
	ExecTimeout  time.Duration
	// PollInterval is used for agent and exec polling (default 3s).
	PollInterval time.Duration
	// IPWait bounds waiting for a DHCP address to show up (default 2m).
	IPWait time.Duration
}

func (r *Runner) defaults() {
	if r.Resolver == nil {
		r.Resolver = CurrentAppResolver
	}
	if r.Audit == nil {
		r.Audit = audit.NopRecorder{}
	}
	if r.History == nil {
		r.History = nopHistory{}
	}
	if r.Log == nil {
		r.Log = slog.New(slog.DiscardHandler)
	}
	if r.TaskTimeout <= 0 {
		r.TaskTimeout = 30 * time.Minute
	}
	if r.AgentTimeout <= 0 {
		r.AgentTimeout = 15 * time.Minute
	}
	if r.ExecTimeout <= 0 {
		r.ExecTimeout = time.Hour
	}
	if r.PollInterval <= 0 {
		r.PollInterval = 3 * time.Second
	}
	if r.IPWait <= 0 {
		r.IPWait = 2 * time.Minute
	}
}

// Run implements jobs.Handler.
func (r *Runner) Run(ctx context.Context, job *jobs.Job, lw *jobs.LogWriter) (any, error) {
	var req Request
	if err := job.DecodePayload(&req); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return r.Deploy(ctx, job.ID, job.CreatedBy, req, lw)
}

// deployment holds the state of one run.
type deployment struct {
	r       *Runner
	req     Request
	jobID   string
	actor   string
	log     Logger
	c       PVE
	node    string
	vmid    int
	created bool
	ips     []string
}

// Deploy runs the full deployment and records history and audit.
func (r *Runner) Deploy(ctx context.Context, jobID, actor string, req Request, log Logger) (*Result, error) {
	r.defaults()
	d := &deployment{r: r, req: req, jobID: jobID, actor: actor, log: log}
	// Make sure the history row exists before Finished updates it, even if
	// the job starts before the enqueuing request records it (Queued is
	// idempotent).
	if herr := r.History.Queued(ctx, jobID, req, actor); herr != nil {
		r.Log.Warn("deploy history", "job_id", jobID, "err", herr)
	}
	res, err := d.run(ctx)

	cleaned := false
	if err != nil {
		log.Printf("ERROR: %v", err)
		cleaned = d.cleanup()
	}
	status := StatusSucceeded
	errMsg := ""
	if err != nil {
		status, errMsg = StatusFailed, err.Error()
	}
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if herr := r.History.Finished(hctx, jobID, status, errMsg, d.ips, cleaned); herr != nil {
		r.Log.Warn("deploy history", "job_id", jobID, "err", herr)
	}
	ev := audit.Event{
		Actor: actor, Action: "deploy.vm", Target: fmt.Sprintf("vm:%s/%d", req.Cluster, d.vmid),
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"job_id": jobID, "name": req.Name, "node": d.node, "template_vmid": req.TemplateVMID,
			"os": req.OS, "apps": req.Apps, "cleaned_up": cleaned},
	}
	if err != nil {
		ev.Outcome, ev.Reason = audit.OutcomeFailure, truncate(err.Error(), 300)
	}
	if aerr := r.Audit.Record(hctx, ev); aerr != nil {
		r.Log.Warn("audit deploy.vm", "job_id", jobID, "err", aerr)
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *deployment) step(n int, format string, a ...any) {
	d.log.Printf("[%d] "+format, append([]any{n}, a...)...)
}

func (d *deployment) run(ctx context.Context) (*Result, error) {
	req, r := d.req, d.r
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	d.log.Printf("Deploying %q from template %s on cluster %s", req.Name, templateLabel(req), req.Cluster)

	// Decrypt secrets up front so a bad payload fails before anything is created.
	adminPW, err := OpenSecret(r.Sealer, req.RequestID, "admin_password", req.Windows.AdminPassword)
	if err != nil {
		return nil, errors.New("cannot unseal the Administrator password")
	}
	domainPW, err := OpenSecret(r.Sealer, req.RequestID, "domain_password", req.Windows.DomainPassword)
	if err != nil {
		return nil, errors.New("cannot unseal the domain-join password")
	}

	var steps []InstallStep
	if len(req.Apps) > 0 {
		steps, err = r.Resolver().Resolve(ctx, req.OS, req.Apps)
		if err != nil {
			return nil, fmt.Errorf("resolve apps: %w", err)
		}
		for _, s := range steps {
			if err := s.Validate(); err != nil {
				return nil, err
			}
			if len(s.Script) > maxScriptBytes || len(s.VerifyScript) > maxScriptBytes {
				return nil, fmt.Errorf("install step %q: script larger than %d bytes", s.Name, maxScriptBytes)
			}
		}
		d.log.Printf("Resolved %d install step(s) for apps: %s", len(steps), strings.Join(req.Apps, ", "))
	}

	if d.c, err = r.Clients.Client(ctx, req.Cluster); err != nil {
		return nil, fmt.Errorf("cluster %s: %w", req.Cluster, err)
	}

	// 1. Template sanity.
	tpl, err := d.c.VMConfig(ctx, req.TemplateNode, req.TemplateVMID)
	if err != nil {
		return nil, fmt.Errorf("read template %d: %w", req.TemplateVMID, err)
	}
	if !tpl.IsTemplate() {
		return nil, fmt.Errorf("VM %d is not a template", req.TemplateVMID)
	}
	if tplOS := osOf(tpl); tplOS != req.OS {
		return nil, fmt.Errorf("template %d is a %s template but the request is for %s", req.TemplateVMID, tplOS, req.OS)
	}

	// 2. Clone.
	d.node = req.Node
	if d.node == "" {
		d.node = req.TemplateNode
	}
	d.vmid = req.VMID
	if d.vmid == 0 {
		if d.vmid, err = d.c.NextID(ctx); err != nil {
			return nil, fmt.Errorf("next VMID: %w", err)
		}
	}
	mode := "full"
	if req.LinkedClone {
		mode = "linked"
	}
	d.step(1, "Cloning template %d -> VM %d %q on node %s (%s clone)", req.TemplateVMID, d.vmid, req.Name, d.node, mode)
	if err := r.History.Running(ctx, d.jobID, req, d.actor, d.node, d.vmid); err != nil {
		r.Log.Warn("deploy history", "job_id", d.jobID, "err", err)
	}
	upid, err := d.c.Clone(ctx, req.TemplateNode, req.TemplateVMID, proxmox.CloneOptions{
		NewID: d.vmid, Name: req.Name, Target: d.node, Storage: req.Storage, Pool: req.Pool, Full: !req.LinkedClone,
		Description: fmt.Sprintf("Deployed by PerfectImage (job %s) from template %s by %s at %s.",
			d.jobID, templateLabel(req), d.actor, time.Now().UTC().Format(time.RFC3339)),
	})
	if err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	d.created = true
	if err := waitTask(ctx, d.c, upid, r.TaskTimeout); err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	d.step(1, "Clone finished")

	// 3. Configure.
	cfg, err := d.c.VMConfig(ctx, d.node, d.vmid)
	if err != nil {
		return nil, fmt.Errorf("read VM config: %w", err)
	}
	params, summary := d.configParams(cfg)
	d.step(2, "Configuring VM: %s", strings.Join(summary, ", "))
	upid, err = d.c.SetConfig(ctx, d.node, d.vmid, params)
	if err != nil {
		return nil, fmt.Errorf("configure: %w", err)
	}
	if err := waitTask(ctx, d.c, upid, r.TaskTimeout); err != nil {
		return nil, fmt.Errorf("configure: %w", err)
	}

	// 4. Disk.
	if req.DiskGB > 0 {
		disk := cfg.BootDisk()
		cur := cfg.DiskSizeBytes(disk)
		want := int64(req.DiskGB) << 30
		switch {
		case disk == "":
			d.step(3, "No boot disk found; skipping resize")
		case want > cur:
			d.step(3, "Resizing %s from %s to %dG", disk, humanBytes(cur), req.DiskGB)
			upid, err := d.c.ResizeDisk(ctx, d.node, d.vmid, disk, strconv.Itoa(req.DiskGB)+"G")
			if err != nil {
				return nil, fmt.Errorf("resize disk: %w", err)
			}
			if err := waitTask(ctx, d.c, upid, r.TaskTimeout); err != nil {
				return nil, fmt.Errorf("resize disk: %w", err)
			}
		default:
			d.step(3, "Disk %s is already %s (>= %dG); not resizing", disk, humanBytes(cur), req.DiskGB)
		}
	}

	// 5. Start and wait for the agent.
	d.step(4, "Starting VM %d", d.vmid)
	if upid, err = d.c.Start(ctx, d.node, d.vmid); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	if err := waitTask(ctx, d.c, upid, r.TaskTimeout); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	if err := d.waitAgent(ctx, 5); err != nil {
		return nil, err
	}
	d.refreshIPs(ctx, req.IPMode != IPStatic)

	// 6. Windows customization.
	if req.OS == OSWindows {
		if err := d.customizeWindows(ctx, cfg, adminPW, domainPW); err != nil {
			return nil, err
		}
	}

	// 7. Apps.
	for i, s := range steps {
		d.step(7, "Installing %s (%d/%d, %s)", s.Name, i+1, len(steps), s.Shell)
		code, err := d.runScript(ctx, s.Shell, s.Script, "")
		if err != nil {
			return nil, fmt.Errorf("install %s: %w", s.Name, err)
		}
		if code != 0 {
			return nil, fmt.Errorf("install %s: script exited with code %d", s.Name, code)
		}
		if s.VerifyScript != "" {
			d.step(7, "Verifying %s", s.Name)
			code, err := d.runScript(ctx, s.Shell, s.VerifyScript, "")
			if err != nil {
				return nil, fmt.Errorf("verify %s: %w", s.Name, err)
			}
			if code != 0 {
				return nil, fmt.Errorf("verify %s: exited with code %d", s.Name, code)
			}
		}
		d.step(7, "%s installed", s.Name)
	}

	d.refreshIPs(ctx, false)
	d.log.Printf("Deployment of %q (VM %d on %s) succeeded. IP addresses: %s", req.Name, d.vmid, d.node, orNone(d.ips))
	return &Result{Cluster: req.Cluster, Node: d.node, VMID: d.vmid, Name: req.Name, IPAddresses: d.ips, Apps: req.Apps}, nil
}

func osOf(cfg proxmox.VMConfig) string {
	if cfg.IsWindows() {
		return OSWindows
	}
	return OSLinux
}

// configParams builds the SetConfig parameters and a log-safe summary.
func (d *deployment) configParams(cfg proxmox.VMConfig) (url.Values, []string) {
	req := d.req
	p := url.Values{}
	var sum []string
	if req.Cores > 0 {
		p.Set("cores", strconv.Itoa(req.Cores))
		sum = append(sum, fmt.Sprintf("cores=%d", req.Cores))
	}
	if req.MemoryMB > 0 {
		p.Set("memory", strconv.Itoa(req.MemoryMB))
		sum = append(sum, fmt.Sprintf("memory=%dM", req.MemoryMB))
	}
	if req.Bridge != "" {
		model := "virtio"
		if cur := cfg.Get("net0"); cur != "" {
			first, _, _ := strings.Cut(cur, ",")
			if m, _, _ := strings.Cut(first, "="); m != "" {
				model = m
			}
		}
		net := model + ",bridge=" + req.Bridge
		if req.VLAN > 0 {
			net += ",tag=" + strconv.Itoa(req.VLAN)
		}
		p.Set("net0", net)
		sum = append(sum, "net0="+net)
	}
	p.Set("agent", "1")
	tags := []string{TagDeployed}
	for _, t := range cfg.Tags() {
		if t != TagTemplate && t != TagDeployed {
			tags = append(tags, t)
		}
	}
	p.Set("tags", strings.Join(tags, ";"))

	useCI := req.OS == OSLinux || cfg.HasCloudInit()
	if req.OS == OSLinux && !cfg.HasCloudInit() {
		if st := d.ciStorage(cfg); st != "" {
			p.Set(freeIDESlot(cfg), st+":cloudinit")
			sum = append(sum, "added cloud-init drive on "+st)
		} else {
			useCI = false
			d.log.Printf("WARNING: template has no cloud-init drive and no storage is known; skipping cloud-init")
		}
	}
	if useCI {
		ci := proxmox.CloudInit{IPConfig: map[int]string{0: d.ipConfig()}, SearchDomain: req.SearchDomain,
			Nameserver: strings.Join(req.DNSServers, " ")}
		if req.OS == OSLinux {
			ci.User = req.Linux.User
			ci.SSHKeys = req.Linux.SSHKeys
		}
		ci.Apply(p)
		sum = append(sum, "ipconfig0="+d.ipConfig())
		if ci.User != "" {
			sum = append(sum, "ciuser="+ci.User)
		}
		if len(ci.SSHKeys) > 0 {
			sum = append(sum, fmt.Sprintf("%d SSH key(s)", len(ci.SSHKeys)))
		}
		if ci.Nameserver != "" {
			sum = append(sum, "nameserver="+ci.Nameserver)
		}
	}
	return p, sum
}

func (d *deployment) ipConfig() string {
	if d.req.IPMode != IPStatic {
		return "ip=dhcp"
	}
	v := "ip=" + d.req.IPCIDR
	if d.req.Gateway != "" {
		v += ",gw=" + d.req.Gateway
	}
	if pfx, err := netip.ParsePrefix(d.req.IPCIDR); err == nil && pfx.Addr().Is6() {
		v = strings.Replace(v, "ip=", "ip6=", 1)
		v = strings.Replace(v, ",gw=", ",gw6=", 1)
	}
	return v
}

// ciStorage picks the storage for a new cloud-init drive.
func (d *deployment) ciStorage(cfg proxmox.VMConfig) string {
	if d.req.Storage != "" && !d.req.LinkedClone {
		return d.req.Storage
	}
	if disk := cfg.BootDisk(); disk != "" {
		if st, _, ok := strings.Cut(cfg.Get(disk), ":"); ok {
			return st
		}
	}
	return ""
}

func freeIDESlot(cfg proxmox.VMConfig) string {
	for _, k := range []string{"ide2", "ide0", "ide1", "ide3"} {
		if cfg.Get(k) == "" {
			return k
		}
	}
	return "scsi30"
}

// fatalPVE reports errors that retrying cannot fix.
func fatalPVE(err error) bool {
	return errors.Is(err, proxmox.ErrUnauthorized) || errors.Is(err, proxmox.ErrForbidden) ||
		errors.Is(err, proxmox.ErrNotFound) || errors.Is(err, context.Canceled)
}

// waitAgent polls the guest agent until it answers.
func (d *deployment) waitAgent(ctx context.Context, n int) error {
	d.step(n, "Waiting up to %s for the QEMU guest agent", d.r.AgentTimeout)
	deadline := time.Now().Add(d.r.AgentTimeout)
	start := time.Now()
	lastNote := start
	for {
		err := d.c.AgentPing(ctx, d.node, d.vmid)
		if err == nil {
			d.step(n, "Guest agent is up after %s", time.Since(start).Round(time.Second))
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("guest agent: %w (last error: %v)", cerr, err)
		}
		if fatalPVE(err) {
			return fmt.Errorf("guest agent: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("guest agent did not answer within %s (is qemu-guest-agent installed in the template?): %w",
				d.r.AgentTimeout, err)
		}
		if time.Since(lastNote) >= time.Minute {
			d.step(n, "Still waiting for the guest agent (%s)", time.Since(start).Round(time.Second))
			lastNote = time.Now()
		}
		if err := sleep(ctx, d.r.PollInterval); err != nil {
			return err
		}
	}
}

// refreshIPs reads guest addresses; with waitV4 it waits up to IPWait for a
// non-link-local IPv4 address (DHCP).
func (d *deployment) refreshIPs(ctx context.Context, waitV4 bool) {
	deadline := time.Now().Add(d.r.IPWait)
	for {
		ifs, err := d.c.AgentNetworkInterfaces(ctx, d.node, d.vmid)
		if err == nil {
			d.ips = guestIPs(ifs)
		}
		if !waitV4 || hasV4(d.ips) || time.Now().After(deadline) || ctx.Err() != nil {
			if err != nil {
				d.log.Printf("Could not read guest IP addresses: %v", err)
			} else {
				d.log.Printf("Guest IP addresses: %s", orNone(d.ips))
			}
			return
		}
		if sleep(ctx, d.r.PollInterval) != nil {
			return
		}
	}
}

func guestIPs(ifs []proxmox.AgentInterface) []string {
	var out []string
	for _, i := range ifs {
		if i.Name == "lo" || strings.HasPrefix(strings.ToLower(i.Name), "loopback") {
			continue
		}
		for _, a := range i.IPAddresses {
			ip, err := netip.ParseAddr(a.Address)
			if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func hasV4(ips []string) bool {
	for _, s := range ips {
		if ip, err := netip.ParseAddr(s); err == nil && ip.Is4() {
			return true
		}
	}
	return false
}

const rebootMarker = "PERFECTIMAGE_REBOOT_REQUIRED"

// customizeWindows sets the Administrator password, hostname, optional
// static IP (when the template has no cloud-init drive) and domain join.
func (d *deployment) customizeWindows(ctx context.Context, cfg proxmox.VMConfig, adminPW, domainPW string) error {
	w := d.req.Windows
	staticNoCI := d.req.IPMode == IPStatic && !cfg.HasCloudInit()
	if adminPW == "" && w.Hostname == "" && w.Domain == "" && !staticNoCI {
		return nil
	}
	var what []string
	if adminPW != "" {
		what = append(what, "Administrator password")
	}
	if w.Hostname != "" {
		what = append(what, "hostname "+w.Hostname)
	}
	if staticNoCI {
		what = append(what, "static IP "+d.req.IPCIDR)
	}
	if w.Domain != "" {
		what = append(what, "join domain "+w.Domain)
	}
	d.step(6, "Customizing Windows: %s", strings.Join(what, ", "))
	script := windowsCustomizeScript(d.req, staticNoCI)
	// Secrets travel on stdin only (never argv or the script file).
	stdin := adminPW + "\n" + domainPW + "\n"
	var out strings.Builder
	code, err := d.runScriptCapture(ctx, ShellPowerShell, script, stdin, &out)
	if err != nil {
		return fmt.Errorf("windows customization: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("windows customization exited with code %d", code)
	}
	if strings.Contains(out.String(), rebootMarker) {
		d.step(6, "Rebooting to apply hostname/domain changes")
		upid, err := d.c.Reboot(ctx, d.node, d.vmid)
		if err != nil {
			return fmt.Errorf("reboot: %w", err)
		}
		if err := waitTask(ctx, d.c, upid, d.r.TaskTimeout); err != nil {
			return fmt.Errorf("reboot: %w", err)
		}
		if err := d.waitAgent(ctx, 6); err != nil {
			return err
		}
		d.refreshIPs(ctx, d.req.IPMode != IPStatic)
	}
	return nil
}

// psQuote returns s as a single-quoted PowerShell literal.
func psQuote(s string) string {
	r := strings.NewReplacer("'", "''", "\u2018", "\u2018\u2018", "\u2019", "\u2019\u2019",
		"\u201a", "\u201a\u201a", "\u201b", "\u201b\u201b")
	return "'" + r.Replace(s) + "'"
}

func windowsCustomizeScript(req Request, staticIP bool) string {
	w := req.Windows
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$adminPw = [Console]::In.ReadLine()\n$domainPw = [Console]::In.ReadLine()\n$reboot = $false\n")
	b.WriteString(`if ($adminPw) {
  $admin = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' } | Select-Object -First 1
  $admin | Set-LocalUser -Password (ConvertTo-SecureString $adminPw -AsPlainText -Force)
  $admin | Enable-LocalUser
  Write-Output ('Password set for local account ' + $admin.Name)
}
`)
	if staticIP {
		pfx, _ := netip.ParsePrefix(req.IPCIDR)
		fmt.Fprintf(&b, `$nic = Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object -First 1
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily %[1]s -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
$ipArgs = @{ InterfaceIndex = $nic.ifIndex; IPAddress = %[2]s; PrefixLength = %[3]d }
`, map[bool]string{true: "IPv4", false: "IPv6"}[pfx.Addr().Is4()], psQuote(pfx.Addr().String()), pfx.Bits())
		if req.Gateway != "" {
			fmt.Fprintf(&b, "$ipArgs.DefaultGateway = %s\n", psQuote(req.Gateway))
		}
		b.WriteString("New-NetIPAddress @ipArgs | Out-Null\nWrite-Output ('Static IP configured on ' + $nic.Name)\n")
		if len(req.DNSServers) > 0 {
			q := make([]string, len(req.DNSServers))
			for i, s := range req.DNSServers {
				q[i] = psQuote(s)
			}
			fmt.Fprintf(&b, "Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses @(%s)\n", strings.Join(q, ","))
		}
	}
	fmt.Fprintf(&b, "$newName = %s\n", psQuote(w.Hostname))
	b.WriteString("$rename = $newName -and ($env:COMPUTERNAME -ne $newName)\n")
	if w.Domain != "" {
		fmt.Fprintf(&b, `$cred = New-Object System.Management.Automation.PSCredential(%s, (ConvertTo-SecureString $domainPw -AsPlainText -Force))
$joinArgs = @{ DomainName = %s; Credential = $cred; Force = $true }
if ($rename) { $joinArgs.NewName = $newName }
`, psQuote(w.DomainUser), psQuote(w.Domain))
		if w.DomainOU != "" {
			fmt.Fprintf(&b, "$joinArgs.OUPath = %s\n", psQuote(w.DomainOU))
		}
		fmt.Fprintf(&b, "Add-Computer @joinArgs\nWrite-Output ('Joined domain ' + %s)\n$reboot = $true\n", psQuote(w.Domain))
	} else {
		b.WriteString("if ($rename) { Rename-Computer -NewName $newName -Force; Write-Output ('Renamed computer to ' + $newName); $reboot = $true }\n")
	}
	b.WriteString("if ($reboot) { Write-Output '" + rebootMarker + "' }\n")
	return b.String()
}

// runScript runs a script in the guest and streams its output to the job log.
func (d *deployment) runScript(ctx context.Context, shell, script, stdin string) (int, error) {
	return d.runScriptCapture(ctx, shell, script, stdin, nil)
}

// runScriptCapture runs script with the given shell via the guest agent.
//
//   - bash: the script is fed on stdin to "/bin/bash -s" when stdin is empty;
//     otherwise it is written to a temp file first.
//   - powershell: the script is always written to a temp .ps1 file (stdin
//     scripts break multi-line constructs) and run with -File; stdin then
//     carries only data (e.g. passwords).
//
// Output lines are logged (and copied to capture if non-nil).
func (d *deployment) runScriptCapture(ctx context.Context, shell, script, stdin string, capture *strings.Builder) (int, error) {
	if len(script) > maxScriptBytes || len(stdin) > maxScriptBytes {
		return 0, fmt.Errorf("script larger than %d bytes", maxScriptBytes)
	}
	name := "perfectimage-" + NewRequestID()[:12]
	var cmd []string
	var cleanup []string
	input := stdin
	switch shell {
	case ShellBash:
		if stdin == "" {
			cmd, input = []string{"/bin/bash", "-s"}, script
		} else {
			path := "/tmp/" + name + ".sh"
			if err := d.c.AgentFileWrite(ctx, d.node, d.vmid, path, script); err != nil {
				return 0, fmt.Errorf("write script: %w", err)
			}
			cmd, cleanup = []string{"/bin/bash", path}, []string{"/bin/rm", "-f", path}
		}
	case ShellPowerShell:
		path := `C:\Windows\Temp\` + name + ".ps1"
		if err := d.c.AgentFileWrite(ctx, d.node, d.vmid, path, script); err != nil {
			return 0, fmt.Errorf("write script: %w", err)
		}
		cmd = []string{"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}
		cleanup = []string{"cmd.exe", "/c", "del", "/f", "/q", path}
	default:
		return 0, fmt.Errorf("unsupported shell %q", shell)
	}
	code, err := d.exec(ctx, cmd, input, capture)
	if len(cleanup) > 0 {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		if _, cerr := d.exec(cctx, cleanup, "", nil); cerr != nil {
			d.log.Printf("WARNING: could not remove temporary script: %v", cerr)
		}
		cancel()
	}
	return code, err
}

// exec starts cmd via the guest agent and polls until it exits.
func (d *deployment) exec(ctx context.Context, cmd []string, input string, capture *strings.Builder) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.r.ExecTimeout)
	defer cancel()
	pid, err := d.c.AgentExec(ctx, d.node, d.vmid, cmd, input)
	if err != nil {
		return 0, fmt.Errorf("guest exec: %w", err)
	}
	start := time.Now()
	lastNote := start
	for {
		st, err := d.c.AgentExecStatus(ctx, d.node, d.vmid, pid)
		if err != nil && (fatalPVE(err) || ctx.Err() != nil) {
			return 0, fmt.Errorf("guest exec status: %w", err)
		}
		if err == nil && bool(st.Exited) {
			d.emit(st.OutData, "", capture)
			d.emit(st.ErrData, "stderr: ", nil)
			if st.OutTruncated || st.ErrTruncated {
				d.log.Printf("    (output truncated by the guest agent)")
			}
			if st.Signal != 0 {
				return -1, fmt.Errorf("killed by signal %d", st.Signal)
			}
			return int(st.ExitCode), nil
		}
		if time.Since(lastNote) >= time.Minute {
			d.log.Printf("    still running (%s)", time.Since(start).Round(time.Second))
			lastNote = time.Now()
		}
		if err := sleep(ctx, d.r.PollInterval); err != nil {
			return 0, fmt.Errorf("guest exec: %w", err)
		}
	}
}

func (d *deployment) emit(out, prefix string, capture *strings.Builder) {
	if capture != nil {
		capture.WriteString(out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\r\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || line == rebootMarker {
			continue
		}
		d.log.Printf("    %s%s", prefix, line)
	}
}

// cleanup destroys the VM if it was created and cleanup was requested.
func (d *deployment) cleanup() bool {
	if !d.created {
		return false
	}
	if !d.req.CleanupOnFailure {
		d.log.Printf("VM %d left in place for inspection (cleanup on failure not selected)", d.vmid)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	d.log.Printf("Cleanup: destroying VM %d on %s", d.vmid, d.node)
	if st, err := d.c.VMStatus(ctx, d.node, d.vmid); err == nil && st.Status == "running" {
		if upid, err := d.c.Stop(ctx, d.node, d.vmid); err == nil {
			_ = waitTask(ctx, d.c, upid, 5*time.Minute)
		}
	} else if errors.Is(err, proxmox.ErrNotFound) {
		d.log.Printf("Cleanup: VM %d does not exist", d.vmid)
		return true
	}
	upid, err := d.c.DeleteVM(ctx, d.node, d.vmid)
	if err == nil {
		err = waitTask(ctx, d.c, upid, 5*time.Minute)
	}
	if err != nil {
		d.log.Printf("Cleanup FAILED: %v (remove VM %d manually)", err, d.vmid)
		return false
	}
	d.log.Printf("Cleanup: VM %d destroyed", d.vmid)
	return true
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<40 && n%(1<<40) == 0:
		return fmt.Sprintf("%dT", n>>40)
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', -1, 64) + "G"
	case n >= 1<<20:
		return fmt.Sprintf("%dM", n>>20)
	}
	return strconv.FormatInt(n, 10)
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "(none reported)"
	}
	return strings.Join(s, ", ")
}

func itoa(i int) string { return strconv.Itoa(i) }
