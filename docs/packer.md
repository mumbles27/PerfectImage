# Packer builds

`internal/packer` turns a catalog image plus a set of apps into a Proxmox VE
VM template using HashiCorp Packer and the `hashicorp/proxmox` plugin
(`proxmox-iso` builder).

## Requirements on the PerfectImage host

- **packer**: the service looks for it in this order:
  1. `packer.binary`, which must be an absolute path.
  2. `packer` in `PATH`.
  3. If `packer.version` is set, the release zip downloaded from
     `packer.releases_url` into `<work_dir>/bin/<version>/`. The zip's SHA-256
     must match `packer.version_sha256`, or the release's `SHA256SUMS` file
     when no hash is pinned.
- **Network access**:
  - Each build runs `packer init`, which downloads the proxmox plugin into
    `<work_dir>/plugins` once. It also needs network access whenever a Linux
    ISO has to be downloaded.
  - Linux builds serve their unattended-install files from Packer's built-in
    HTTP server. The build VM must be able to reach the PerfectImage host
    on a port in Packer's default range (8000–9000).
- **xorriso** (or `mkisofs`/`genisoimage`, `oscdimg` on Windows) is needed for
  Windows images, because their `autounattend.xml` is attached as a generated
  CD.

## Configuration (`packer:` section)

| Key | Default | Meaning |
|---|---|---|
| `binary` | "" | absolute path to packer |
| `work_dir` | `<data_dir>/packer` | `builds/<id>/` workdirs, `plugins/`, `cache/`, `config/`, `bin/` |
| `version`, `version_sha256`, `releases_url` | "", "", releases.hashicorp.com | optional pinned download |
| `build_timeout` | `4h` | upper bound for init + validate + build |
| `interrupt_grace` | `2m` | after cancel or timeout, how long packer gets to delete the build VM before it is killed |
| `keep_workdir` | `on_failure` | `never`, `on_failure` or `always` |
| `catalog_reload_interval` | `10s` | how often catalog override directories are polled (negative disables) |

## What a build does

The `packer.build` job does the following:

1. **Checks the request.** It checks the request against the current
   catalog and resolves the apps: the image's `default_apps`, plus the
   selected apps and bundles, plus their dependencies.
2. **Fetches credentials.** It asks the installed `ClusterCreds` provider for
   the cluster's API endpoint and token (see [Credentials](#credentials)).
3. **Generates and seals a build password.** It generates a random 24-character
   password for the build user. The password is sealed with the master key and
   stored in `packer_builds.build_password` with AAD `packer_build:<id>`;
   `Service.BuildPassword` returns it.
4. **Renders `<work_dir>/builds/<build id>/`:**
   - a copy of the image directory;
   - one script per app in `perfectimage/apps/NN-<app>.sh|.ps1`;
   - `build.pkr.hcl`, with its `# @perfectimage:apps` line replaced by one
     `shell` or `powershell` provisioner per app. Apps with
     `reboot_required` are followed by a `windows-restart` provisioner on
     Windows, or a reboot and reconnect on Linux;
   - `perfectimage.auto.pkrvars.hcl` (mode 0600), which holds only
     non-secret variables.
5. **Runs packer** in the workdir:
   - `packer init .`
   - `packer validate .`
   - `packer build -color=false -machine-readable -on-error=cleanup .`

   The machine-readable output is turned into readable job-log lines, and
   the template VMID is read from the `artifact,…,id` event.
6. **Records the result.** It updates `packer_builds` (status, artifact,
   error), stores a `BuildResult` as the job result and records an
   `image.build.finish` audit event. Submitting a build records
   `image.build.start`.
7. **Cleans up.** It removes the workdir according to `keep_workdir`.

Every build ends with the `proxmox-iso` builder converting the VM into a
template tagged `perfectimage` plus the image's tags. The
`template_description` names the image, the date, the build id and the apps.

**Cancellation.**

- On Linux, Packer gets SIGINT, so it can stop and delete the build VM. After
  `interrupt_grace` it is killed together with its plugin processes.
- On Windows, a CTRL_BREAK is attempted, falling back to killing the process.
- Hitting `build_timeout` works the same way, and the job fails with
  "build timed out".

**Secrets.**

- Proxmox credentials reach packer only through `PROXMOX_URL`,
  `PROXMOX_USERNAME` and `PROXMOX_TOKEN`. The build password reaches it only
  through `PKR_VAR_build_password`.
- Neither ever appears in argv or in the vars file.
- Packer inherits only an allowlist of the service's environment, such as
  PATH, proxies and temp directories.
- Both values are also replaced with `<redacted>` in every job-log line.

## Credentials

The `proxmox` package owns the cluster records and their sealed tokens. It
supplies them to packer through this interface:

```go
type ClusterCreds interface {
	Creds(ctx context.Context, cluster string) (endpoint, tokenID, secret string, insecure bool, err error)
}
packer.SetClusterCreds(provider) // e.g. from the proxmox plugin's Init
```

- `endpoint` may be the bare `https://host:8006` or end in `/api2/json`.
- `tokenID` is `user@realm!tokenname`.
- If the provider also implements `packer.Inventory`
  (`Clusters`, `Nodes`, `Storages`), the wizard offers those lists.
  Otherwise the cluster list comes from `proxmox.clusters` in the config.
- If it also implements `packer.MediaInventory` (`Bridges`, `ISOStorages`,
  `ISOs`, `Defaults`), the wizard offers bridges and ISO files too, and
  prefills the cluster's saved defaults. `internal/integration` implements
  both on top of the Proxmox cluster registry.

Until a provider is installed, builds fail with `ErrNoCreds`.

The token needs enough privileges to create, configure and convert VMs on the
node and to allocate space on the disk and ISO storages. For example, use
`PVEVMAdmin` plus `PVEDatastoreUser` on the storages and `Sys.Modify` for ISO
uploads.

## Build wizard

`/build` (`images.view`) lists the build history from the `packer_builds`
table. Users with `images.build` also get the wizard, which has these
sections:

1. **Operating system**: the catalog image, plus the **edition** for images
   that list `editions` (Windows Server: Standard/Datacenter, Desktop
   Experience or Core). The edition sets the `windows_image_name` variable.
2. **Target**: cluster, node, disk storage, bridge and ISO storage. With the
   Proxmox integration these are live drop-downs. Changing the image,
   cluster or node re-renders the form (`POST /build/form`, htmx) and keeps
   everything already entered. The node defaults to the cluster's saved
   default node. Disk storage and bridge fall back to the cluster's saved
   defaults when the image's own defaults do not exist on that node. If a
   cluster cannot be reached, the form says so and falls back to free text.
3. **Hardware and install media**: cores, memory and disk overrides, and the
   install / virtio-win ISO, picked from the ISOs on every ISO storage of
   the node. PerfectImage's own temporary `pi-seed-*` ISOs are hidden.
4. **OS settings**: time zone, locale and keyboard, plus **install all OS
   updates** (see below). Empty fields keep the installer defaults.
5. **Apps and bundles**: only those available for the image's OS are shown,
   with an option to skip the image's default apps.
6. **Post-install script**: optional Bash (Linux, run as root) or PowerShell
   (Windows, run as the build administrator), up to 64 KiB, optionally
   followed by a restart. A non-zero exit code fails the build. The script
   is stored with the build record and shown on `/build/<id>`; the
   `image.build.start` audit event records its SHA-256 and size. Do not put
   secrets in it.
7. **Template**: template name (regenerated on image change unless you
   edited it) and VMID (`0` means the next free VMID).

Submitting enqueues a `packer.build` job and redirects to its live log at
`/jobs/<id>`. `/build/<id>` shows a single build, including its OS settings
and post-install script.

### Provisioning order

All generated steps replace the image's `# @perfectimage:apps` marker, so
they run after base provisioning and before cleanup / generalization:

1. **OS settings** (`_os-settings`):
   - Linux: `timedatectl` (or `/etc/localtime`), `locale-gen` +
     `update-locale` on Debian/Ubuntu or a glibc langpack + `localectl` on
     RHEL, and the XKB layout in `/etc/default/keyboard` or `localectl`.
   - Windows: `Set-TimeZone` and `Set-WinSystemLocale` (followed by a
     restart when the locale changes). The values are also saved to
     `C:\Windows\Panther\perfectimage-settings.json`. The catalog's
     `sysprep.ps1` reads that file and writes `TimeZone` and
     `Microsoft-Windows-International-Core` (`InputLocale`, `SystemLocale`,
     `UserLocale`) into the oobeSystem pass of the generalize answer file,
     so every clone and every new user profile gets them.
2. **OS updates** (`_os-updates`):
   - Linux: `apt-get dist-upgrade` or `dnf upgrade --refresh`, then a
     reboot.
   - Windows: three Windows Update passes through the Windows Update Agent
     API, each followed by a `windows-restart`. The API refuses to download
     or install from a WinRM network logon, so these provisioners use
     Packer's **elevated** mode (`elevated_user` / `elevated_password` =
     the build user, run as a scheduled task). Updates that fail are
     reported in the log and retried by the next pass; they do not fail the
     build. Expect an hour or more on a fresh ISO.
3. **Apps**, in dependency order.
4. **Post-install script** (`_post-install`), plus a restart if requested.

Step ids starting with `_` are reserved for these generated steps (catalog
app ids cannot start with `_`). The build record's `Apps` lists only catalog
apps.

Values are validated per OS before anything is rendered:

| Field | Linux | Windows |
|---|---|---|
| Time zone | IANA name (`UTC`, `Europe/Berlin`) | Windows id (`W. Europe Standard Time`, see `tzutil /l`) |
| Locale | `en-US`, `en_US` or `en_US.UTF-8` (rendered as `en_US.UTF-8`) | same forms (rendered as `en-US`) |
| Keyboard | XKB layout with optional variant (`de`, `us-intl`) | input locale (`de-DE` or `0407:00000407`) |

## Image template contract

Every `images/<id>/` directory needs:

- `image.pkr.hcl`:
  - a `packer { required_plugins { proxmox = { source = "github.com/hashicorp/proxmox", version = "~> 1.2" } } }` block;
  - the variables below;
  - one `source "proxmox-iso" "image"`.

  Do **not** set `proxmox_url`, `username` or `token` here; the plugin reads
  them from the environment.
- `build.pkr.hcl`:
  - a `build` block using `source.proxmox-iso.image`;
  - exactly one line `# @perfectimage:apps`, placed after base provisioning
    and before cleanup / generalization.

  Linux images must give the build user **passwordless sudo** for the
  duration of the build (generated provisioners use
  `execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"`), and remove it
  during cleanup.
- Variables that PerfectImage always sets:

  ```
  proxmox_node proxmox_insecure vm_id template_name template_description tags
  cores memory disk_size storage_pool bridge iso_storage_pool iso_file
  iso_url iso_checksum            (only when iso_file is empty)
  virtio_iso_file                 (windows)
  build_password                  (sensitive, from PKR_VAR_build_password)
  ```

  The image may declare more variables with defaults, such as
  `build_username` or `windows_image_name`.
- Answer files: render them with `templatefile()` into `http_content` (Linux)
  or into `additional_iso_files { cd_content = {...} }` (Windows), so the
  build password is never written to disk in the catalog.
- Generalization:
  - Linux: clean the machine-id, run `cloud-init clean`, remove SSH host keys
    and lock the build user.
  - Windows: run Sysprep `/generalize /oobe` last.

To test locally:

```sh
cd catalog/images/<id>
packer init . && packer fmt -check . && packer validate -syntax-only .
# full validation of every rendered starter image (needs packer + plugin):
PERFECTIMAGE_PACKER_VALIDATE=1 go test ./internal/packer -run TestRenderedTemplatesValidate
```

To update the golden files after an intended change to the rendered output:

```sh
go test ./internal/packer -run TestRenderGolden -update
```

CI runs `packer init`, `validate -syntax-only` and `fmt -check` on every
image, then `catalog validate`, then the full rendered-template validation.

## After the build (for deploy)

- **Linux templates** come with a cloud-init drive. Configure users and keys
  per clone with Proxmox cloud-init.
- **Windows templates** are sysprepped. The build user's password is the
  sealed build password. Reset it on each clone, for example through the
  QEMU guest agent (`agent/set-user-password`), before you depend on WinRM.
- WinRM over HTTPS on port 5986 is set up during the build. Sysprep's
  specialize pass removes that listener, so deploy must set up its own
  remote management.
