# Catalog: images, apps and bundles

The catalog describes what PerfectImage can build (images) and install
(apps and bundles). Code: `internal/catalog`. Built-in content: `catalog/`.

## Sources and overrides

The catalog is built from layers, merged in order:

1. The **embedded catalog**: the repository's `catalog/` directory, compiled
   into the binary.
2. Each directory in `catalog.dirs` from the config file, in order. The
   default is `<data_dir>/catalog`.

Every layer has the same layout:

```
images/<id>/image.yaml      image metadata
images/<id>/*.pkr.hcl       Packer template (see docs/packer.md)
images/<id>/http/ ...       unattended-install files (Linux)
images/<id>/answer/ ...     autounattend template (Windows)
images/<id>/scripts/ ...    provisioning scripts
apps/<id>.yaml              one app per file
bundles/<id>.yaml           one bundle per file
```

When two layers define the same id, the later layer wins. This works for
images, apps and bundles. To change a built-in app, copy its YAML into an
override directory and edit the copy. To pin a different ISO, copy the whole
image directory.

The service polls the override directories every
`packer.catalog_reload_interval` (default 10s) and reloads them when a file's
size or modification time changes. If the new files have problems, the
service still loads them, skips the files it cannot parse, and lists every
problem at the top of `/catalog` for users with `catalog.manage`.

## Validating

```sh
perfectimage catalog validate                      # embedded + catalog.dirs from --config
perfectimage catalog validate --dir ./my-catalog   # embedded + this directory
perfectimage catalog validate --no-embedded --dir catalog
```

Each problem is printed as `file:line: message`, and the command exits 1 if
it finds any. It checks:

- YAML syntax, and unknown or misspelled keys (decoding is strict)
- required fields
- the format of every value that ends up in a generated script, including
  package names, URLs, sha256 sums and ids
- that each id matches its file or directory name
- unknown dependencies, dependency cycles and unknown bundle members
- that an image's `default_apps` are available for the image's OS
- that `build.pkr.hcl` contains the apps marker exactly once

## Images

`images/<id>/image.yaml`:

```yaml
id: ubuntu-24.04               # must equal the directory name
name: Ubuntu Server 24.04 LTS
description: Optional text.
os_family: linux               # linux | windows
os: ubuntu
version: "24.04"
distro_family: debian          # linux only: debian (apt) | rhel (dnf)
arch: amd64                    # amd64 | arm64
iso:
  url: https://releases.ubuntu.com/24.04/ubuntu-24.04.3-live-server-amd64.iso
  checksum: file:https://releases.ubuntu.com/24.04/SHA256SUMS   # or sha256:<hex>
  # iso_file: local:iso/ubuntu.iso                              # ISO already on Proxmox (instead of url)
  # virtio_iso_file: local:iso/virtio-win.iso                   # windows only, required
firmware: uefi                 # bios | uefi
tpm: false                     # requires uefi
resources: {cores: 2, memory: 4096, disk: 32G, storage: local-lvm, bridge: vmbr0}
communicator: ssh              # ssh (linux) | winrm (windows)
default_apps: [curl, htop]     # installed unless the build skips them
tags: [linux, ubuntu]          # become Proxmox tags (perfectimage is always added)
```

Windows ISOs are licensed media, so you upload them to Proxmox storage
yourself and either set `iso.iso_file` or enter the file in the build wizard.
The virtio-win ISO comes from the Fedora virtio-win project.

The Packer files beside `image.yaml` must follow the contract in
[docs/packer.md](packer.md#image-template-contract). The easiest way to add
an image is to copy the starter image closest to what you need:

| Starter | Install media | Unattended install |
|---|---|---|
| `ubuntu-24.04` | official ISO URL + SHA256SUMS | autoinstall (`http/user-data.pkrtpl`) |
| `debian-13` | official netinst URL + SHA256SUMS | preseed (`http/preseed.pkrtpl`) |
| `rocky-9` | official boot ISO URL + CHECKSUM | kickstart (`http/ks.pkrtpl`) |
| `windows-server-2022`, `windows-server-2025` | user-supplied `iso_file` | `answer/autounattend.pkrtpl.xml` |
| `windows-11` (UEFI + TPM) | user-supplied `iso_file` | `answer/autounattend.pkrtpl.xml` |

When a point release changes an ISO file name, update both `iso.url` in
`image.yaml` and the `iso_url` default in `image.pkr.hcl`. A build always
uses the value from `image.yaml`.

## Apps

`apps/<id>.yaml`:

```yaml
id: git                        # must equal the file name; [a-z0-9._-]
name: Git
category: dev                  # browser | dev | utility | runtime | container | security | media
description: Distributed version control system.
homepage: https://git-scm.com
depends_on: []                 # app ids installed first
reboot_required: false         # reboot after installing (windows-restart / systemctl reboot)
install:
  windows:                     # tried in order until one installs AND verifies
    - winget: {id: Git.Git}            # optional: source (winget|msstore), version, scope (machine|user)
      verify: 'if (Test-Path "$env:ProgramFiles\Git\cmd\git.exe") { exit 0 } else { exit 1 }'
    - choco: {package: git}            # optional: version; Chocolatey is bootstrapped if missing
      verify: '...'
    - msi:                             # or exe:
        url: https://example.com/app.msi
        sha256: <64 hex>
        args: /qn /norestart           # msi default; exe has no default
      verify: '...'
    - powershell:
        script: |
          # any PowerShell; a non-zero exit code means failure
      verify: '...'
  linux:
    - apt:
        packages: [git]
        repo:                          # optional vendor repository
          name: vendor                 # -> /etc/apt/keyrings/vendor.gpg, sources.list.d/vendor.list
          url: https://packages.example.com/apt
          key_url: https://packages.example.com/key.asc   # armored or binary
          suite: "{codename}"          # {codename} = VERSION_CODENAME of the guest
          components: main
      verify: command -v git
    - dnf:
        packages: [git]
        repo: {name: vendor, url: "https://packages.example.com/rpm/$releasever/$basearch", key_url: https://packages.example.com/key.asc}
      verify: command -v git
    - snap: {name: code, classic: true, channel: stable}
      verify: snap list code
    - flatpak: {id: org.example.App}   # remote defaults to flathub
      verify: flatpak info org.example.App
    - tarball:
        url: https://example.com/tool-1.2.3-linux-amd64.tar.gz
        sha256: <64 hex>
        dest: /opt/tool                # must be below /opt or /usr/local; replaced on install
        strip_components: 1
        bin: [bin/tool]                # symlinked into /usr/local/bin
      verify: test -x /opt/tool/bin/tool
    - shell:
        script: |
          curl -fsSL https://example.com/install.sh | sh
      distros: [rhel]                  # optional for snap/flatpak/tarball/shell: debian | rhel
      verify: command -v tool
```

Rules and tips:

- **verify is required for every method.** It runs after the method, and
  the method only counts as successful if it exits 0. Before any method
  runs, every verify command is tried once, and if one passes the app counts
  as already installed.
- **Windows verify commands run in a new `powershell.exe` process**, so
  write them to exit with a code. `Test-Path` alone always exits 0. Prefer
  checking a file path, because `PATH` is not refreshed inside the build
  session.
- `apt` methods only apply to `debian`-family images and `dnf` methods only
  to `rhel`-family images. Restrict the other Linux methods with `distros`.
- Generated scripts run as root (Linux) or Administrator (Windows).
- Values are quoted when they are inserted into scripts. `shell` and
  `powershell` scripts are not changed, so anyone with `catalog.manage` can
  run arbitrary code on build VMs. Grant that permission accordingly.
- `msi`, `exe` and `tarball` downloads are checked against `sha256`.
  Use versioned URLs: a "latest" URL breaks as soon as the vendor publishes
  a new release.

## Bundles

`bundles/<id>.yaml`:

```yaml
id: developer-base
name: Developer base
description: Common developer tooling.
apps: [git, vscode, python, nodejs, go, docker, jq, curl]
```

A bundle id must not match an app id. When an image is selected, the build
wizard only offers a bundle's apps that support that image's OS.

## Editing in the UI

At `/catalog`, anyone with `catalog.view` can browse and search images,
apps and bundles. Users with `catalog.manage` can also:

- **create**, **edit** or **clone** an app or bundle as YAML. Editing a
  built-in item creates an override file.
- **validate** a definition without saving it.
- **delete an override**, so the built-in definition applies again.

Saves go to the **last** directory in `catalog.dirs`. A definition must pass
validation in the context of the whole catalog before it is written. Files
are written atomically with mode 0640. Every save, delete or failed save
records an audit event:

- `catalog.app.create`, `catalog.app.update`, `catalog.app.clone`
- `catalog.bundle.create`, `catalog.bundle.update`, `catalog.bundle.clone`
- `catalog.app.delete`, `catalog.bundle.delete`
- `catalog.reload`

## Using the catalog from Go

```go
steps, err := catalog.Resolve(catalog.Linux, catalog.DistroDebian, []string{"developer-base", "jq"})
// []catalog.InstallStep{AppID, Name, Shell ("bash"|"powershell"), Script, VerifyScript, RebootRequired}
```

`Resolve` expands bundle ids and adds dependencies, which come first in the
result. It returns an error wrapping `ErrUnknownApp`, `ErrCycle` or
`ErrUnsupported`. The package-level function uses the shared store that the
catalog plugin loads. Code that has its own `*catalog.Store` can call
`store.Catalog().Resolve(...)` instead.
