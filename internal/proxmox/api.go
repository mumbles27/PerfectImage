package proxmox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Version returns the PVE version (GET /version). Useful as a connection test.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	err := c.get(ctx, "/version", nil, &v)
	return v, err
}

// ClusterResources lists cluster resources; typ is "vm", "node", "storage",
// "sdn" or "" for all.
func (c *Client) ClusterResources(ctx context.Context, typ string) ([]Resource, error) {
	q := url.Values{}
	if typ != "" {
		q.Set("type", typ)
	}
	var out []Resource
	err := c.get(ctx, "/cluster/resources", q, &out)
	return out, err
}

// Templates returns all QEMU templates in the cluster.
func (c *Client) Templates(ctx context.Context) ([]Resource, error) {
	res, err := c.ClusterResources(ctx, "vm")
	if err != nil {
		return nil, err
	}
	var out []Resource
	for _, r := range res {
		if r.Type == "qemu" && bool(r.Template) {
			out = append(out, r)
		}
	}
	return out, nil
}

// Nodes lists cluster nodes.
func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	var out []Node
	err := c.get(ctx, "/nodes", nil, &out)
	return out, err
}

// Storages lists enabled storages on node, optionally filtered by content
// type (images, iso, vztmpl, ...).
func (c *Client) Storages(ctx context.Context, node, content string) ([]Storage, error) {
	q := url.Values{"enabled": {"1"}}
	if content != "" {
		q.Set("content", content)
	}
	var out []Storage
	err := c.get(ctx, "/nodes/"+seg(node)+"/storage", q, &out)
	return out, err
}

// StorageContent lists volumes on storage, filtered by content ("iso",
// "vztmpl", "images", "" for all).
func (c *Client) StorageContent(ctx context.Context, node, storage, content string) ([]StorageContent, error) {
	q := url.Values{}
	if content != "" {
		q.Set("content", content)
	}
	var out []StorageContent
	err := c.get(ctx, "/nodes/"+seg(node)+"/storage/"+seg(storage)+"/content", q, &out)
	return out, err
}

// ISOs lists ISO images on storage.
func (c *Client) ISOs(ctx context.Context, node, storage string) ([]StorageContent, error) {
	return c.StorageContent(ctx, node, storage, "iso")
}

// ContainerTemplates lists container templates (vztmpl) on storage.
func (c *Client) ContainerTemplates(ctx context.Context, node, storage string) ([]StorageContent, error) {
	return c.StorageContent(ctx, node, storage, "vztmpl")
}

// Networks lists node network interfaces; typ e.g. "any_bridge" or "".
func (c *Client) Networks(ctx context.Context, node, typ string) ([]NetworkIface, error) {
	q := url.Values{}
	if typ != "" {
		q.Set("type", typ)
	}
	var out []NetworkIface
	err := c.get(ctx, "/nodes/"+seg(node)+"/network", q, &out)
	return out, err
}

// UploadOptions configures UploadISO.
type UploadOptions struct {
	// Content is "iso" (default), "vztmpl" or "import".
	Content string
	// Checksum and ChecksumAlgorithm (md5, sha1, sha224, sha256, sha384,
	// sha512) make PVE verify the upload.
	Checksum          string
	ChecksumAlgorithm string
	// Size is the number of bytes r will provide. When zero it is taken from
	// r if r is an *os.File or has a Len() method (bytes/strings readers).
	Size int64
}

// UploadISO streams r to storage as filename and returns the task UPID.
// The upload is bounded only by ctx (no per-request timeout) and is never
// retried.
//
// The request is sent with a fixed Content-Length: Proxmox rejects chunked
// transfer encoding ("501 chunked transfer encoding not supported"), so the
// size of r must be known (see UploadOptions.Size).
func (c *Client) UploadISO(ctx context.Context, node, storage, filename string, r io.Reader, o UploadOptions) (string, error) {
	if filename == "" || strings.ContainsAny(filename, `/\`) {
		return "", errors.New("proxmox: invalid upload filename")
	}
	if o.Content == "" {
		o.Content = "iso"
	}
	size := o.Size
	if size <= 0 {
		switch v := r.(type) {
		case interface{ Len() int }:
			size = int64(v.Len())
		case *os.File:
			st, err := v.Stat()
			if err != nil {
				return "", fmt.Errorf("proxmox: upload size: %w", err)
			}
			cur, err := v.Seek(0, io.SeekCurrent)
			if err != nil {
				return "", fmt.Errorf("proxmox: upload size: %w", err)
			}
			size = st.Size() - cur
		default:
			return "", errors.New("proxmox: upload size unknown (set UploadOptions.Size)")
		}
	}

	// Build the multipart framing around the file so the total length is
	// known while the file itself is still streamed.
	var head bytes.Buffer
	mw := multipart.NewWriter(&head)
	fields := [][2]string{{"content", o.Content}}
	if o.Checksum != "" {
		// PVE's streaming upload parser needs the algorithm before the
		// checksum; the other order fails with a bare "400 Bad Request".
		fields = append(fields, [2]string{"checksum-algorithm", o.ChecksumAlgorithm}, [2]string{"checksum", o.Checksum})
	}
	for _, f := range fields {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return "", err
		}
	}
	if _, err := mw.CreateFormFile("filename", filename); err != nil {
		return "", err
	}
	tail := "\r\n--" + mw.Boundary() + "--\r\n" // what mw.Close would write
	body := io.MultiReader(bytes.NewReader(head.Bytes()), &exactReader{r: r, n: size}, strings.NewReader(tail))
	length := int64(head.Len()) + size + int64(len(tail))

	path := "/nodes/" + seg(node) + "/storage/" + seg(storage) + "/upload"
	var upid string
	err := c.send(ctx, http.MethodPost, path, c.base+path, sizedBody{Reader: body, n: length}, mw.FormDataContentType(), 0, &upid)
	return upid, err
}

// sizedBody marks a request body with a known length for send.
type sizedBody struct {
	io.Reader
	n int64
}

// exactReader yields exactly n bytes from r and fails if r ends early, so a
// short source cannot leave the server waiting for the declared length.
type exactReader struct {
	r io.Reader
	n int64
}

func (e *exactReader) Read(p []byte) (int, error) {
	if e.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > e.n {
		p = p[:e.n]
	}
	k, err := e.r.Read(p)
	e.n -= int64(k)
	if err == io.EOF {
		if e.n > 0 {
			return k, io.ErrUnexpectedEOF
		}
		return k, io.EOF
	}
	return k, err
}

// DownloadURLOptions configures DownloadURL.
type DownloadURLOptions struct {
	URL      string
	Filename string
	// Content is "iso" (default), "vztmpl" or "import".
	Content            string
	Checksum           string
	ChecksumAlgorithm  string
	VerifyCertificates *bool // default true on the PVE side
}

// DownloadURL makes the node download o.URL into storage; returns the UPID.
func (c *Client) DownloadURL(ctx context.Context, node, storage string, o DownloadURLOptions) (string, error) {
	if o.URL == "" || o.Filename == "" {
		return "", errors.New("proxmox: download-url needs url and filename")
	}
	if o.Content == "" {
		o.Content = "iso"
	}
	f := url.Values{"url": {o.URL}, "filename": {o.Filename}, "content": {o.Content}}
	if o.Checksum != "" {
		f.Set("checksum", o.Checksum)
		f.Set("checksum-algorithm", o.ChecksumAlgorithm)
	}
	if o.VerifyCertificates != nil {
		f.Set("verify-certificates", boolParam(*o.VerifyCertificates))
	}
	var upid string
	err := c.post(ctx, "/nodes/"+seg(node)+"/storage/"+seg(storage)+"/download-url", f, &upid)
	return upid, err
}

// DeleteVolume deletes a storage volume (e.g. "local:iso/seed.iso") and
// returns the task UPID (empty when PVE deletes synchronously).
func (c *Client) DeleteVolume(ctx context.Context, node, volid string) (string, error) {
	storage, _, ok := strings.Cut(volid, ":")
	if !ok || storage == "" {
		return "", fmt.Errorf("proxmox: invalid volume id %q", volid)
	}
	var upid string
	err := c.delete(ctx, "/nodes/"+seg(node)+"/storage/"+seg(storage)+"/content/"+seg(volid), nil, &upid)
	return upid, err
}

// ListVMs lists QEMU VMs on node.
func (c *Client) ListVMs(ctx context.Context, node string) ([]VM, error) {
	var out []VM
	err := c.get(ctx, "/nodes/"+seg(node)+"/qemu", nil, &out)
	return out, err
}

// VMConfig returns the current VM configuration.
func (c *Client) VMConfig(ctx context.Context, node string, vmid int) (VMConfig, error) {
	var out VMConfig
	err := c.get(ctx, vmPath(node, vmid)+"/config", nil, &out)
	return out, err
}

// VMStatus returns the current VM status.
func (c *Client) VMStatus(ctx context.Context, node string, vmid int) (VMStatus, error) {
	var out VMStatus
	err := c.get(ctx, vmPath(node, vmid)+"/status/current", nil, &out)
	return out, err
}

// CloneOptions configures Clone.
type CloneOptions struct {
	NewID       int
	Name        string
	Description string
	// Target node (default: source node).
	Target string
	// Storage for a full clone's disks (ignored for linked clones).
	Storage string
	Pool    string
	// Full makes an independent copy; false makes a linked clone (template
	// sources only).
	Full bool
	// Format for full clones (raw, qcow2, vmdk).
	Format string
}

// Clone clones vmid on node and returns the task UPID.
func (c *Client) Clone(ctx context.Context, node string, vmid int, o CloneOptions) (string, error) {
	if o.NewID <= 0 {
		return "", errors.New("proxmox: clone needs a new VMID")
	}
	f := url.Values{"newid": {strconv.Itoa(o.NewID)}, "full": {boolParam(o.Full)}}
	setIf(f, "name", o.Name)
	setIf(f, "description", o.Description)
	setIf(f, "target", o.Target)
	setIf(f, "pool", o.Pool)
	if o.Full {
		setIf(f, "storage", o.Storage)
		setIf(f, "format", o.Format)
	}
	var upid string
	err := c.post(ctx, vmPath(node, vmid)+"/clone", f, &upid)
	return upid, err
}

// SetConfig updates VM options asynchronously (POST .../config). It returns
// a UPID when PVE started a task (e.g. disk allocation), else "".
func (c *Client) SetConfig(ctx context.Context, node string, vmid int, params url.Values) (string, error) {
	var upid string
	err := c.post(ctx, vmPath(node, vmid)+"/config", params, &upid)
	return upid, err
}

// CloudInit holds cloud-init options for SetConfig.
type CloudInit struct {
	User string
	// Password is hashed by PVE for Linux guests. Avoid where SSH keys work.
	Password string
	// SSHKeys are OpenSSH public keys, one per entry.
	SSHKeys []string
	// IPConfig maps a NIC index to an ipconfigN value, e.g.
	// "ip=dhcp" or "ip=10.0.0.5/24,gw=10.0.0.1".
	IPConfig     map[int]string
	Nameserver   string
	SearchDomain string
}

// Apply adds the cloud-init options to params.
func (ci CloudInit) Apply(params url.Values) {
	setIf(params, "ciuser", ci.User)
	setIf(params, "cipassword", ci.Password)
	if keys := strings.TrimSpace(strings.Join(ci.SSHKeys, "\n")); keys != "" {
		params.Set("sshkeys", EncodeSSHKeys(keys))
	}
	for i, v := range ci.IPConfig {
		params.Set("ipconfig"+strconv.Itoa(i), v)
	}
	setIf(params, "nameserver", ci.Nameserver)
	setIf(params, "searchdomain", ci.SearchDomain)
}

// EncodeSSHKeys percent-encodes keys the way PVE expects for the sshkeys
// option (every byte outside [A-Za-z0-9-_.~] escaped, spaces as %20). The
// form encoder then encodes the result once more, which PVE decodes twice.
func EncodeSSHKeys(keys string) string {
	return strings.ReplaceAll(url.QueryEscape(keys), "+", "%20")
}

// ResizeDisk sets disk (e.g. "scsi0") to size ("40G" absolute or "+8G").
// Returns a UPID on PVE versions that run it as a task, else "".
func (c *Client) ResizeDisk(ctx context.Context, node string, vmid int, disk, size string) (string, error) {
	var upid string
	err := c.put(ctx, vmPath(node, vmid)+"/resize", url.Values{"disk": {disk}, "size": {size}}, &upid)
	return upid, err
}

// Start starts the VM and returns the task UPID.
func (c *Client) Start(ctx context.Context, node string, vmid int) (string, error) {
	return c.statusAction(ctx, node, vmid, "start", nil)
}

// Stop hard-stops the VM and returns the task UPID.
func (c *Client) Stop(ctx context.Context, node string, vmid int) (string, error) {
	return c.statusAction(ctx, node, vmid, "stop", nil)
}

// Shutdown asks the guest to power off (ACPI or agent). timeout <= 0 uses
// the PVE default; forceStop hard-stops after the timeout.
func (c *Client) Shutdown(ctx context.Context, node string, vmid int, timeout time.Duration, forceStop bool) (string, error) {
	f := url.Values{}
	if timeout > 0 {
		f.Set("timeout", strconv.Itoa(int(timeout.Seconds())))
	}
	if forceStop {
		f.Set("forceStop", "1")
	}
	return c.statusAction(ctx, node, vmid, "shutdown", f)
}

// Reboot reboots the guest.
func (c *Client) Reboot(ctx context.Context, node string, vmid int) (string, error) {
	return c.statusAction(ctx, node, vmid, "reboot", nil)
}

func (c *Client) statusAction(ctx context.Context, node string, vmid int, action string, f url.Values) (string, error) {
	var upid string
	err := c.post(ctx, vmPath(node, vmid)+"/status/"+action, f, &upid)
	return upid, err
}

// ConvertToTemplate converts a stopped VM into a template. Returns a UPID
// when PVE runs it as a task, else "".
func (c *Client) ConvertToTemplate(ctx context.Context, node string, vmid int) (string, error) {
	var upid string
	err := c.post(ctx, vmPath(node, vmid)+"/template", nil, &upid)
	return upid, err
}

// DeleteVM destroys the VM (purging it from jobs/ACLs and destroying
// unreferenced disks) and returns the task UPID.
func (c *Client) DeleteVM(ctx context.Context, node string, vmid int) (string, error) {
	var upid string
	err := c.delete(ctx, vmPath(node, vmid),
		url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, &upid)
	return upid, err
}

// TaskStatus returns the status of a task.
func (c *Client) TaskStatus(ctx context.Context, upid string) (TaskStatus, error) {
	u, err := ParseUPID(upid)
	if err != nil {
		return TaskStatus{}, err
	}
	var out TaskStatus
	err = c.get(ctx, "/nodes/"+seg(u.Node)+"/tasks/"+seg(upid)+"/status", nil, &out)
	return out, err
}

// TaskLog returns up to limit log lines starting at line start.
func (c *Client) TaskLog(ctx context.Context, upid string, start, limit int) ([]TaskLogLine, error) {
	u, err := ParseUPID(upid)
	if err != nil {
		return nil, err
	}
	q := url.Values{"start": {strconv.Itoa(start)}}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out []TaskLogLine
	err = c.get(ctx, "/nodes/"+seg(u.Node)+"/tasks/"+seg(upid)+"/log", q, &out)
	return out, err
}

// WaitTask polls the task until it finishes or ctx ends. A task finishing
// with a non-OK exit status returns a *TaskError (with the final status).
// An empty upid (synchronous operation) returns immediately.
func (c *Client) WaitTask(ctx context.Context, upid string) (TaskStatus, error) {
	if upid == "" {
		return TaskStatus{Status: "stopped", ExitStatus: "OK"}, nil
	}
	u, err := ParseUPID(upid)
	if err != nil {
		return TaskStatus{}, err
	}
	t := time.NewTicker(c.taskPoll)
	defer t.Stop()
	for {
		st, err := c.TaskStatus(ctx, upid)
		if err != nil {
			return st, err
		}
		if !st.Running() {
			if st.OK() {
				return st, nil
			}
			return st, &TaskError{UPID: upid, Node: u.Node, Type: u.Type, ExitStatus: st.ExitStatus}
		}
		select {
		case <-ctx.Done():
			return st, fmt.Errorf("proxmox: waiting for task %s: %w", u.Type, ctx.Err())
		case <-t.C:
		}
	}
}

// AgentPing checks that the guest agent answers.
func (c *Client) AgentPing(ctx context.Context, node string, vmid int) error {
	return c.post(ctx, vmPath(node, vmid)+"/agent/ping", nil, nil)
}

// AgentNetworkInterfaces returns the guest's network interfaces.
func (c *Client) AgentNetworkInterfaces(ctx context.Context, node string, vmid int) ([]AgentInterface, error) {
	var out struct {
		Result []AgentInterface `json:"result"`
	}
	err := c.get(ctx, vmPath(node, vmid)+"/agent/network-get-interfaces", nil, &out)
	return out.Result, err
}

// AgentExec starts command in the guest, feeding input to its stdin, and
// returns the guest PID. Arguments go through the guest agent, never a
// shell on the PVE host; still, keep secrets in input, not in command.
func (c *Client) AgentExec(ctx context.Context, node string, vmid int, command []string, input string) (int, error) {
	if len(command) == 0 {
		return 0, errors.New("proxmox: agent exec needs a command")
	}
	f := url.Values{"command": command}
	setIf(f, "input-data", input)
	var out struct {
		PID FlexInt `json:"pid"`
	}
	err := c.post(ctx, vmPath(node, vmid)+"/agent/exec", f, &out)
	return int(out.PID), err
}

// AgentExecStatus returns the status of a command started with AgentExec.
func (c *Client) AgentExecStatus(ctx context.Context, node string, vmid, pid int) (ExecStatus, error) {
	var out ExecStatus
	err := c.get(ctx, vmPath(node, vmid)+"/agent/exec-status", url.Values{"pid": {strconv.Itoa(pid)}}, &out)
	return out, err
}

// AgentFileWrite writes content to file in the guest (max ~60 KiB).
func (c *Client) AgentFileWrite(ctx context.Context, node string, vmid int, file, content string) error {
	return c.post(ctx, vmPath(node, vmid)+"/agent/file-write", url.Values{"file": {file}, "content": {content}}, nil)
}

// NextID returns the next free VMID.
func (c *Client) NextID(ctx context.Context) (int, error) {
	var id FlexInt
	err := c.get(ctx, "/cluster/nextid", nil, &id)
	return int(id), err
}

// Pools lists resource pools.
func (c *Client) Pools(ctx context.Context) ([]Pool, error) {
	var out []Pool
	err := c.get(ctx, "/pools", nil, &out)
	return out, err
}

func boolParam(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func setIf(v url.Values, k, s string) {
	if s != "" {
		v.Set(k, s)
	}
}
