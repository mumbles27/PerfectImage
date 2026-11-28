# PerfectImage

PerfectImage is a web console for building and deploying virtual machine
images. You pick an operating system, apps, OS settings and an optional
post-install script, and PerfectImage drives HashiCorp Packer to build a
template. It can then deploy VMs from that template, with networking,
cloud-init or Windows customization, and post-deploy apps and scripts. It
ships as a single Go binary that runs as a **Windows service** or a
**systemd unit** and serves an embedded web UI over HTTPS.

> Status: **Proxmox VE is supported end to end.** VMware vSphere, Hyper-V,
> VirtualBox, AWS and Azure are planned: see
> [docs/roadmap.md](docs/roadmap.md).

## Features

**Build images** (`/build`; see [docs/packer.md](docs/packer.md))

- Starter images: Ubuntu 24.04, Debian 13, Rocky 9, Windows 11 and Windows
  Server 2022/2025 (Standard or Datacenter, Desktop Experience or Core).
- Targets come live from the chosen cluster: nodes, storages, bridges and
  ISO files, with each cluster's saved defaults filled in.
- OS settings: time zone, locale, keyboard, and an option to install all OS
  updates (apt/dnf, or Windows Update with restarts). On Windows the
  settings are carried through Sysprep to every clone.
- 30+ catalog apps and bundles (winget, Chocolatey, MSI/EXE, apt, dnf,
  snap, flatpak, tarballs), each with a verify check.
- An optional Bash or PowerShell **post-install script**, with an optional
  restart afterwards.
- Unattended installs, using seed ISOs or answer CDs, so the build VM
  doesn't need to reach back to the server.
- Live build logs, history and an audit trail.

**Deploy VMs** (`/deploy`; see [docs/proxmox.md](docs/proxmox.md))

- Full or linked clones with CPU, memory, disk, bridge/VLAN and DHCP or a
  static IP.
- Linux: a cloud-init user and SSH keys.
- Windows: an Administrator password, hostname and domain join.
- Post-deploy apps and an optional post-deploy script, run through the
  QEMU guest agent.

**Connect any Proxmox** (Settings → Proxmox)

- Add, test, edit and delete clusters in the UI.
- API tokens are sealed at rest. TLS can use a pinned CA or a pinned
  certificate fingerprint; insecure mode is for labs only.

**Platform**

- Local users with TOTP MFA, OIDC and LDAP sign-in, API tokens, and
  built-in and custom roles.
- A hash-chained audit log, SIEM forwarding (syslog/CEF, HTTP, Splunk HEC)
  and encrypted scheduled backups.
- A single static binary with pure-Go SQLite, HTTPS by default, a strict
  CSP, CSRF tokens, and AES-256-GCM secrets protected by DPAPI or a key
  file.
- A server-rendered UI (`html/template` + htmx), so no Node toolchain is
  needed.

## Quickstart (development)

You need Go (see `go.mod` for the minimum version).

```sh
git clone https://github.com/mumbles27/PerfectImage
cd PerfectImage
go run ./cmd/perfectimage serve --config config.example.yaml
# -> https://127.0.0.1:8443  (self-signed cert; data in ./data)
curl -k https://127.0.0.1:8443/healthz
```

On first start the service creates an `admin` user with a one-time password.
It prints the password to the console and writes it to
`<data_dir>/secrets/initial-admin-password.txt`; see
[docs/auth.md](docs/auth.md). For quick local UI work you can instead set
`auth.dev_allow_all: true` in a **local copy** of the config. That setting
is only accepted on loopback listeners.

To run builds, the host also needs `packer` (see
[docs/packer.md](docs/packer.md#requirements-on-the-perfectimage-host)) and
a Proxmox API token (see [docs/proxmox.md](docs/proxmox.md)).

Useful targets:

```sh
make ci             # gofmt check, go vet (linux+windows), race tests, builds
make build          # bin/perfectimage
make build-windows  # dist/perfectimage-windows-amd64.exe
make run            # serve with config.example.yaml
```

## Installation

### Linux (systemd)

```sh
sudo useradd --system --home-dir /var/lib/perfectimage --shell /usr/sbin/nologin perfectimage
sudo install -m 0755 dist/perfectimage-linux-amd64 /usr/local/bin/perfectimage
sudo install -d -m 0750 -g perfectimage /etc/perfectimage
sudo install -m 0640 -g perfectimage config.example.yaml /etc/perfectimage/config.yaml
sudoedit /etc/perfectimage/config.yaml   # data_dir: /var/lib/perfectimage, server.listen: ":8443"
sudo install -m 0644 packaging/perfectimage.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now perfectimage
```

### Windows (service)

Run this from an elevated PowerShell:

```powershell
.\scripts\install-windows.ps1 -Binary .\dist\perfectimage-windows-amd64.exe -Port 8443
```

The script does the following:

- Installs the binary to `C:\Program Files\PerfectImage`.
- Creates `%ProgramData%\PerfectImage`, restricted to SYSTEM and
  Administrators, and seeds `config.yaml` there.
- Registers and starts the `PerfectImage` service.
- Opens the firewall port.

To remove the service, run it with `-Uninstall`.

## CLI

```
perfectimage serve      [--config path]   run (foreground, or under SCM/systemd)
perfectimage install    [--config path]   register the service
perfectimage uninstall | start | stop | status
perfectimage version
perfectimage backup | restore             encrypted backup / restore (docs/backup.md)
perfectimage catalog validate             check catalog images, apps and bundles
perfectimage user reset-admin             recover the admin account
```

The default config path is `/etc/perfectimage/config.yaml` on Linux and
`%ProgramData%\PerfectImage\config.yaml` on Windows.

## Architecture

See [docs/architecture.md](docs/architecture.md). In short:

```
cmd/perfectimage     CLI dispatch (internal/cli registry) + plugin imports
internal/app         bootstrap, plugins (app.Plugin / app.Deps), service integration
internal/config      YAML config, defaults, validation, per-domain sections
internal/logging     slog JSON, rotating file, Sink fan-out
internal/secrets     AES-256-GCM Sealer, DPAPI / key-file master key
internal/store       SQLite + per-namespace embedded migrations
internal/jobs        persistent job queue, workers, log writer, pub/sub hub
internal/web         router, middleware, templates, htmx, Module interface, core pages
internal/auth        users, sessions, MFA, OIDC/LDAP, API tokens, CSRF
internal/rbac        permissions, built-in roles
internal/audit       Event, Recorder, hash-chained audit log + /audit UI
internal/proxmox     Proxmox VE client, cluster registry, TLS relay, /settings/proxmox
internal/deploy      VM deploy wizard + job (clone, customize, apps, post-deploy script)
internal/packer      build wizard + job (render, OS settings/updates, post-install script, run packer)
internal/catalog     image/app catalog loader, validator, editor
internal/integration wires proxmox -> packer (creds, inventory, seed ISOs) and catalog -> deploy
internal/siem        SIEM forwarders
internal/backup      backup/restore
catalog/             Packer templates and app definitions
```

## Roadmap

Done:

- Foundation: the service, config, secrets, store, jobs and web UI
- Auth
- Proxmox clusters and deploy
- Packer builds with the image and app catalog
- Ops: audit, SIEM and backup
- Build wizard options: live inventory, OS settings, OS updates, Windows
  editions, and post-install and post-deploy scripts

Next:

- **More build targets:** VMware vSphere, Hyper-V, VirtualBox, AWS and
  Azure, behind a common target interface. See
  [docs/roadmap.md](docs/roadmap.md) for the design and the parts that are
  Proxmox-specific today.
- A script library, product keys for more Windows editions, saved build
  presets with scheduled rebuilds, and template versioning.

## Contributing

Read [AGENTS.md](AGENTS.md) before contributing: it covers the branch
workflow, required checks and package ownership.

## License

[MIT](LICENSE)
