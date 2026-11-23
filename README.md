# PerfectImage

PerfectImage builds Proxmox VE VM templates with HashiCorp Packer. It then
deploys VMs from those templates and installs selected applications on Linux
and Windows guests. It ships as a single Go binary that runs as a **Windows
service** or a **systemd unit** and serves an embedded web UI over HTTPS.

> Status: **foundation release.** The service skeleton is in place: config,
> logging, secrets, SQLite store, job queue and web UI shell. Authentication,
> Proxmox, Packer and ops features are being built in phases (see the
> [Roadmap](#roadmap)).

## Features (foundation)

- Single static binary with no CGO, using pure-Go SQLite (modernc.org/sqlite)
- HTTPS by default, with a self-signed certificate generated on first run
- Strict CSP, HSTS and cross-origin CSRF protection
- Persistent background job queue with cancellation and live log streaming
  (Server-Sent Events)
- Structured JSON logging with rotation and pluggable sinks for SIEM
  forwarding
- AES-256-GCM sealing of secrets at rest. The master key is protected by
  DPAPI on Windows and stored in a 0600 key file on Linux.
- Role-based access control: built-in Admin, Operator, Builder and Viewer
  roles with fine-grained permissions
- Server-rendered UI (`html/template` + htmx). No Node toolchain is needed.

## Quickstart (development)

You need Go (see `go.mod` for the minimum version).

```sh
git clone https://github.com/mumbles27/PerfectImage
cd PerfectImage
go run ./cmd/perfectimage serve --config config.example.yaml
# -> https://127.0.0.1:8443  (self-signed cert; data in ./data)
curl -k https://127.0.0.1:8443/healthz
```

Sign-in pages arrive with the auth module. Until then, set
`auth.dev_allow_all: true` in a **local copy** of the config to browse the UI.
This setting is only accepted on loopback listeners.

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
perfectimage backup | restore             (ops phase)
perfectimage catalog validate             (packer phase)
perfectimage user reset-admin             (auth phase)
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
internal/auth        Principal, Authenticator, Authorizer          (auth phase)
internal/rbac        permissions, built-in roles                    (auth phase)
internal/audit       Event, Recorder                                (ops phase)
internal/proxmox     Proxmox VE client                              (proxmox phase)
internal/deploy      VM deploy + app install                        (proxmox phase)
internal/packer      Packer build driver                            (packer phase)
internal/catalog     image/app catalog loader + validator           (packer phase)
internal/siem        SIEM forwarders                                (ops phase)
internal/backup      backup/restore                                 (ops phase)
catalog/             Packer templates and app definitions
```

## Roadmap

1. **Foundation** (this release): service skeleton, config, logging, secrets,
   store/migrations, job queue, web shell, CI.
2. **Auth**:
   - Local users with strong password hashing, sessions, login/logout and
     CSRF tokens
   - Role management with custom roles
   - `user reset-admin`
   - Optional OIDC/LDAP
3. **Proxmox**:
   - Cluster connections with sealed API tokens and pinned CAs
   - Inventory
   - VM deploy from templates (clone, cloud-init / sysprep)
   - Post-deploy app installation for Linux (SSH) and Windows (WinRM)
4. **Packer**:
   - Image catalog (Linux and Windows templates)
   - Build jobs with live logs
   - Template versioning
   - App catalog
   - `catalog validate`
5. **Ops**:
   - Persistent audit log and Audit UI
   - SIEM forwarding (syslog/CEF, HTTP, Splunk HEC)
   - Scheduled backup/restore
   - Metrics

## Contributing

Read [AGENTS.md](AGENTS.md) before contributing: it covers the branch
workflow, required checks and package ownership.

## License

[MIT](LICENSE)
