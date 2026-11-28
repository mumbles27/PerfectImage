# Proxmox VE integration

PerfectImage talks to Proxmox VE (PVE) through its REST API (`/api2/json`)
with an **API token**. This page covers:

- the least-privilege role, user, token and ACLs to create with `pveum`
- TLS verification and pinning
- adding clusters (UI or config)
- what the `deploy.vm` job does and what it needs inside templates
- the Go seams other modules use (`proxmox.Registry`, `deploy.AppResolver`)

## 1. Service account and API token

Run these commands as `root` on any node of the cluster. The names
(`PerfectImage`, `perfectimage@pve`, `deploy`, the `perfectimage` pool and the
storage names) are examples. Change them to match your environment.

### 1.1 Role

The role grants what PerfectImage and Packer need to:

- build templates (create VMs, attach ISOs, type the boot command over the
  console, convert to template)
- deploy VMs (clone, configure, cloud-init, resize, power, guest agent,
  delete)
- upload ISOs and list resources

**Proxmox VE 8.x:**

```sh
pveum role add PerfectImage --privs "\
VM.Allocate,VM.Audit,VM.Clone,\
VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,\
VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,\
VM.Console,VM.Monitor,VM.PowerMgmt,\
Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit,\
SDN.Use,Sys.Audit,Pool.Audit"
```

**Proxmox VE 9.x** removes `VM.Monitor` and splits guest-agent access into
`VM.GuestAgent.*` privileges. PerfectImage runs scripts in the guest
(`agent/exec`) and writes files there (`agent/file-write`), so it needs
`VM.GuestAgent.Unrestricted`:

```sh
pveum role add PerfectImage --privs "\
VM.Allocate,VM.Audit,VM.Clone,\
VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,\
VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,\
VM.Console,VM.PowerMgmt,\
VM.GuestAgent.Audit,VM.GuestAgent.Unrestricted,\
Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit,\
SDN.Use,Sys.Audit,Pool.Audit"
```

Check the privileges your PVE version knows with `pveum role list` before you
run this. If you already created the role, use `pveum role modify PerfectImage
--privs "..."`.

What each group is for:

| Privilege | Used for |
|---|---|
| `VM.Allocate` | create (clone), delete VMs; place VMs into a pool |
| `VM.Clone` | clone templates |
| `VM.Config.*` | CPU, memory, NIC/VLAN, disks and resize, cloud-init, ISO (CD-ROM), options and tags/description, hardware type |
| `VM.PowerMgmt` | start, stop, shutdown, reboot |
| `VM.Console` | Packer `boot_command` (VNC) during template builds |
| `VM.Monitor` (PVE 8) / `VM.GuestAgent.*` (PVE 9) | guest agent ping, IPs, exec, file-write |
| `VM.Audit` | read VM config and status |
| `Datastore.AllocateSpace` | disks for clones and builds |
| `Datastore.AllocateTemplate` | ISO upload and `download-url` |
| `Datastore.Audit` | list storages and ISOs |
| `SDN.Use` | attach NICs to bridges/VNets (enforced since PVE 8) |
| `Sys.Audit` | list nodes, cluster resources and tasks |
| `Pool.Audit` | list resource pools in the deploy wizard |

`download-url` (fetch an ISO straight onto a node) also requires
`Sys.Modify` on `/nodes/<node>`. This privilege is broad, so it is **not** in
the role above. If you want server-side ISO downloads, grant it separately
(see 1.4). Otherwise upload ISOs through PerfectImage instead.

### 1.2 User

Create a `pve`-realm user with no password. It cannot log in to the web UI
and is only used through its token:

```sh
pveum user add perfectimage@pve --comment "PerfectImage service account"
```

### 1.3 API token with privilege separation

```sh
pveum user token add perfectimage@pve deploy --privsep 1 --comment "PerfectImage"
```

The output shows `full-tokenid` (`perfectimage@pve!deploy`) and `value`
(the secret, a UUID). **The secret is shown only once.** Enter it in
**Settings → Proxmox** in PerfectImage. It is sealed (AES-256-GCM) in the
database and never shown or logged again.

With `--privsep 1` the token's effective permissions are the
**intersection** of the user's ACLs and the token's own ACLs. Grant the role
to both (next step). You can then revoke the token alone with
`pveum user token remove perfectimage@pve deploy` without touching the
user.

### 1.4 ACLs

**Simple** (whole cluster):

```sh
pveum acl modify / --users  perfectimage@pve        --roles PerfectImage
pveum acl modify / --tokens 'perfectimage@pve!deploy' --roles PerfectImage
```

**Tighter** (recommended): scope the role to the VMs, the storages and the
bridge zone PerfectImage uses, and give it read-only access to nodes.

```sh
# A pool for everything PerfectImage creates (optional but tidy)
pveum pool add perfectimage --comment "PerfectImage templates and VMs"

# Grant each path to both the user and the token (privilege separation).
for path in /vms /pool/perfectimage /storage/local-lvm /storage/local /sdn/zones/localnetwork; do
  pveum acl modify "$path" --users perfectimage@pve          --roles PerfectImage
  pveum acl modify "$path" --tokens 'perfectimage@pve!deploy' --roles PerfectImage
done
# Read-only node access (node list, cluster resources, task status)
pveum acl modify /nodes --users perfectimage@pve          --roles PVEAuditor
pveum acl modify /nodes --tokens 'perfectimage@pve!deploy' --roles PVEAuditor
```

Paths: `/vms` (all VMs), `/pool/perfectimage` (the pool), `/storage/local-lvm`
(VM disks), `/storage/local` (ISOs and cloud-init drives),
`/sdn/zones/localnetwork` (plain Linux bridges `vmbrX`).

Notes:

- `/vms` covers every VMID. For a smaller scope, put templates and deployed VMs
  in the pool and grant only `/pool/perfectimage`. VMs must then always be
  created in that pool (set **Default pool** on the cluster).
- `/sdn/zones/localnetwork` covers classic `vmbrN` bridges. For SDN VNets,
  grant `/sdn/zones/<zone>` instead (or `/sdn/zones/<zone>/<vnet>`).
- Optional, only for `download-url`:
  ```sh
  pveum role add PerfectImageISO --privs "Sys.Audit,Sys.Modify"
  pveum acl modify /nodes/pve1 --users perfectimage@pve --roles PerfectImageISO
  pveum acl modify /nodes/pve1 --tokens 'perfectimage@pve!deploy' --roles PerfectImageISO
  ```

Check the result:

```sh
pveum user permissions perfectimage@pve
pveum user token permissions perfectimage@pve deploy
```

## 2. TLS verification and pinning

Verification is **on by default**: PerfectImage only connects if the PVE
certificate chains to a trusted CA and matches the endpoint hostname. Pick
one of these modes per cluster:

| Mode | When to use | Settings |
|---|---|---|
| System roots | The node has a publicly trusted cert (for example ACME / Let's Encrypt) | nothing |
| CA pin | The default self-signed setup: each node cert is signed by the cluster CA | CA bundle (PEM) or CA file |
| Fingerprint pin | A single endpoint whose exact certificate you trust | SHA-256 fingerprint |
| Fingerprint + CA | Both conditions must hold | both |
| Insecure | Throw-away labs only | `insecure_skip_verify` |

### CA pin (recommended for default PVE installs)

Every PVE cluster has its own CA at `/etc/pve/pve-root-ca.pem`, and it signs
each node's `pve-ssl.pem`. Copy the CA to the PerfectImage host, or paste it
into the **CA bundle** field:

```sh
scp root@pve1:/etc/pve/pve-root-ca.pem /etc/perfectimage/pve-lab-ca.pem
```

The endpoint hostname (or IP) must appear in the node certificate's SANs.
Check with `openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -ext subjectAltName`.
If it is missing, regenerate the node certificate with
`pvecm updatecerts --force` after fixing `/etc/hosts`, or use a fingerprint pin.

### Fingerprint pin

A pin checks the SHA-256 digest of the leaf certificate (constant-time
comparison). Hostname and chain are not checked unless you also set a CA. Get
the fingerprint on the node:

```sh
pvenode cert info | grep -i fingerprint
# or, for the certificate actually served on 8006:
openssl x509 -noout -fingerprint -sha256 -in /etc/pve/local/pveproxy-ssl.pem 2>/dev/null \
  || openssl x509 -noout -fingerprint -sha256 -in /etc/pve/local/pve-ssl.pem
```

or remotely. Only do this over a network you trust, then compare the result
with the node's own value:

```sh
openssl s_client -connect pve1.example.com:8006 -servername pve1.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Paste it in either form, `AB:CD:...` or plain hex. When a pin does not
match, **Test connection** shows the fingerprint the server presented, which
helps during certificate rotation. Re-pin after **every** certificate renewal.
ACME certificates renew every 60–90 days, so for ACME prefer system roots.

### Insecure mode

`insecure_skip_verify` turns verification off completely. Anyone on the
network path can then impersonate the node and steal the API token.
PerfectImage logs a warning every time it builds such a client and marks the
cluster `INSECURE` in the UI. If a fingerprint is also set, the pin still
applies and the insecure flag is ignored.

## 3. Adding clusters

**UI:** go to **Settings → Proxmox** (permission `proxmox.manage`). Use
**Test connection** to check the endpoint, token and TLS settings before you
save. It calls `/version` and `/nodes`. Every create, update, delete and test
is audited (`proxmox.cluster.*`). The token secret is never shown again. Leave
the field empty when editing to keep the stored secret.

**Config (seeding):** clusters in `proxmox.clusters` are inserted into the
database **the first time each name is seen**. After that the database copy
wins: edits in the UI persist, and clusters deleted in the UI are not
re-created on restart. The token secret can be read once from a 0600
`token_secret_file`. Otherwise add it in the UI.

```yaml
proxmox:
  request_timeout: 30s   # one API call (GETs are retried with backoff)
  task_timeout: 30m      # one PVE task (clone, resize, start, ...)
  agent_timeout: 15m     # waiting for the guest agent after boot
  clusters:
    - name: lab
      endpoint: https://pve1.example.com:8006/api2/json
      token_id: perfectimage@pve!deploy
      token_secret_file: /etc/perfectimage/pve-lab.token
      ca_file: /etc/perfectimage/pve-lab-ca.pem
      default_node: pve1
      default_storage: local-lvm
      default_bridge: vmbr0
      default_pool: perfectimage
```

## 4. Deploying VMs

### Pages

| Path | Permission | Purpose |
|---|---|---|
| `/deploy` | `deploy.run` (viewers are redirected to templates) | wizard |
| `/deploy/templates` | `deploy.view`; delete needs `images.build` | templates on all clusters. PerfectImage-built templates (tag `perfectimage`) show the build metadata from their description (`key: value` lines). |
| `/deploy/history` | `deploy.view` | past deployments with status, VMID and IPs |

### The `deploy.vm` job

1. Resolve the selected apps into install steps. An unknown app fails the job
   before anything is created.
2. Check the template, pick the next free VMID (unless one was given), and
   clone it: full by default, or linked. Set target node, storage and pool.
3. Configure the VM:
   - cores and memory
   - `net0` on the chosen bridge and VLAN tag, keeping the template's NIC model
   - `agent=1`
   - tags `perfectimage-deployed` plus the template's tags
   - Linux: cloud-init `ciuser`, `sshkeys` and `ipconfig0` (DHCP or static),
     plus `nameserver`/`searchdomain`. A cloud-init drive is added when the
     template lacks one.
4. Grow the boot disk to the requested size. Disks are never shrunk.
5. Start the VM and wait for the QEMU guest agent, then read its IPs.
6. Windows only, via the guest agent and PowerShell:
   - set the built-in Administrator password
   - rename the computer
   - set a static IP when the template has no cloud-init drive (cloudbase-init)
   - optionally join a domain
   - reboot if needed
7. Run each install step via guest-agent `exec`:
   - **bash:** the script is piped to `/bin/bash -s`.
   - **PowerShell:** the script is written to `C:\Windows\Temp\perfectimage-*.ps1`,
     run with `powershell.exe -File` and deleted afterwards.
   - A non-zero exit code fails the job. So does a failing `VerifyScript`.
8. Run the optional **post-deploy script** the same way: Bash as root on
   Linux, PowerShell as SYSTEM on Windows, up to 60,000 bytes. A non-zero
   exit code fails the job. The script is part of the job payload, so it
   must not contain secrets.
9. On failure with **Delete the VM if any step fails** checked, stop and
   destroy the VM. Otherwise leave it in place for inspection.

Every step is written to the job log, which streams live at `/jobs/{id}`. The
outcome is audited as `deploy.vm`, and the submit as `deploy.vm.request`.

**Secrets:**

- The Windows Administrator and domain-join passwords are sealed into the job
  payload (aad `deploy.vm:<request id>:<field>`).
- They reach the guest only as **stdin** of the customization script, never
  as argv, in a file, or in the PVE VM config.
- They never appear in job logs, audit events or history.

### Template requirements

- `qemu-guest-agent` installed and enabled. The job waits for it, up to
  `agent_timeout`.
- Linux: cloud-init. The drive is added if missing.
- Windows: PowerShell 5.1+. For static IPs through Proxmox cloud-init you
  also need cloudbase-init; without it, the static IP is set with PowerShell
  instead.
- PerfectImage-built templates carry the `perfectimage` tag and `key: value`
  build metadata lines in the description.

## 5. Go seams

### `proxmox.Registry` and credentials (for Packer)

```go
reg := proxmox.NewRegistry(d.DB, d.Sealer, d.Logger, d.Config.Proxmox)

c, err := reg.Client(ctx, "lab")           // *proxmox.Client, cached per cluster
creds, err := reg.Credentials(ctx, "lab")  // Endpoint, TokenID, Secret, InsecureSkipVerify, CA/fingerprint
cmd.Env = append(os.Environ(), creds.PackerEnv()...) // PROXMOX_URL, PROXMOX_USERNAME, PROXMOX_TOKEN
```

- `Credentials` redacts the secret in `String`, `GoString` and `slog`.
- Pass the values to child processes through the environment, never argv.
- Registries are cheap. Each one notices cluster edits through the row's
  `updated_at`.

### `deploy.AppResolver` (for the catalog)

```go
type InstallStep struct{ Name, Shell /* bash|powershell */, Script, VerifyScript string }

type AppResolver interface {
	Resolve(ctx context.Context, os string /* linux|windows */, appIDs []string) ([]InstallStep, error)
}

// Optional: populates the wizard's app checkboxes.
type AppLister interface {
	Apps(ctx context.Context, os string) ([]deploy.AppInfo, error)
}

deploy.SetAppResolver(catalogResolver) // from the catalog plugin's Init
```

Until a resolver is installed, the stub knows no apps and the wizard shows
"No apps are available".
