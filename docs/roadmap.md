# Roadmap: more build targets

PerfectImage builds and deploys on **Proxmox VE** today. The goal is to build
the same catalog images on more platforms from the same web console:

| Target | Packer builder | Starts from | Status |
|---|---|---|---|
| Proxmox VE | `proxmox-iso` (`hashicorp/proxmox`) | install ISO | **done**: builds, deploy, live inventory |
| VMware vSphere | `vsphere-iso` (`hashicorp/vsphere`) | install ISO | planned |
| Microsoft Hyper-V | `hyperv-iso` (`hashicorp/hyperv`) | install ISO | planned, needs a build agent (see below) |
| Oracle VirtualBox | `virtualbox-iso` (`hashicorp/virtualbox`) | install ISO | planned, needs a build agent |
| Amazon Web Services | `amazon-ebs` (`hashicorp/amazon`) | base AMI | planned |
| Microsoft Azure | `azure-arm` (`hashicorp/azure`) | marketplace image | planned |

This page records where the code is tied to Proxmox today, and the plan for
loosening that. Nothing here is implemented yet.

## Where the code is Proxmox-specific today

1. **Catalog images.** Each `images/<id>/image.pkr.hcl` holds a
   `source "proxmox-iso" "image"` block. `build.pkr.hcl` references
   `source.proxmox-iso.image`.
2. **Variables.** `packer.Vars` emits Proxmox variables: `proxmox_node`,
   `storage_pool`, `bridge`, `iso_storage_pool` and `iso_file`.
3. **Credentials and inventory.** `packer.ClusterCreds`, `packer.Inventory`
   and `packer.MediaInventory` are shaped around a Proxmox cluster and node.
   `internal/integration` implements them on `proxmox.Registry`. Credentials
   reach Packer as `PROXMOX_URL`, `PROXMOX_USERNAME` and `PROXMOX_TOKEN`.
4. **Seed media.** `packer.SeedStore` uploads seed ISOs to Proxmox storage.
5. **Deploy.** `internal/deploy` clones Proxmox templates and customizes
   them through the QEMU guest agent.
6. **Settings UI.** Only `/settings/proxmox` exists. The `proxmox.manage`
   permission guards it.

These parts are already target-neutral and stay as they are:

- the app catalog and install-script generation (`internal/catalog`)
- OS settings, OS updates and post-install scripts (`internal/packer/options.go`)
- the job queue, audit, RBAC and the wizard flow

## Plan

### Step 1: a target seam, with Proxmox as the only implementation

Do this with no change in behavior.

- Add `internal/target` with a `Provider` interface:
  - `Kind() string`: for example `"proxmox"` or `"vsphere"`
  - `Env(ctx, target) ([]string, error)`: Packer credentials as environment
    variables, never argv
  - `Vars(img, req) []packer.Var`: the target-specific variables
  - an optional `Inventory`: a generic list of named *locations* (cluster,
    node, datacenter, region or resource group) and *resources* (storage,
    network, ISO or base image)
  - optional `SeedStore` and `Deployer` implementations
- Store targets in a shared table, `target_targets`, with sealed
  credentials. Move the `proxmox_clusters` rows into it with a new
  migration; the old migrations stay as they are.
- `BuildRequest` gains `Target string` (kind plus name). Old payloads
  without it mean Proxmox.
- Settings gets a **Targets** page with one form per provider kind, plus a
  `targets.manage` permission. Proxmox keeps its current form.

### Step 2: catalog sources per target

- Move each image's source block into `images/<id>/sources/<kind>.pkr.hcl`.
  The renderer copies only the source for the selected target and points
  `build.pkr.hcl` at it.
- `image.yaml` gains a `targets:` list. The wizard offers only targets the
  image supports.
- Cloud targets start from a base image, not an ISO. They get a
  `base_image:` entry per target in `image.yaml`, for example an AMI owner
  and name filter, or an Azure publisher, offer and SKU.
- Generalization depends on the target. It moves from the image's cleanup
  scripts into a per-target step:
  - Proxmox, vSphere, Hyper-V and VirtualBox: Sysprep, or cloud-init clean
  - AWS: EC2Launch v2 sysprep, or cloud-init clean
  - Azure: Sysprep `/mode:vm`, or `waagent -deprovision+user`

### Step 3: ISO-based hypervisors

- **vSphere** is closest to Proxmox: it uses a remote API and ISOs on
  datastores. Inventory covers datacenter, cluster, host, datastore,
  network and content library. Use VMware Tools in place of the QEMU guest
  agent, and VMware's guest operations for deploy.
- **Hyper-V and VirtualBox** builders drive the hypervisor on the machine
  where Packer runs. That needs either PerfectImage installed on the
  Hyper-V or VirtualBox host, or a small **build agent** that runs Packer
  there and streams its log back over mutual TLS. The agent is the
  better long-term design because it also lets one console drive many
  hosts.

### Step 4: clouds

- **AWS** (`amazon-ebs`): credentials as `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY`, or an assumed role. Inventory covers regions,
  subnets, security groups and source AMIs. The artifact is an AMI id, and
  deploy launches an instance.
- **Azure** (`azure-arm`): credentials as `ARM_CLIENT_ID`,
  `ARM_CLIENT_SECRET`, `ARM_TENANT_ID` and `ARM_SUBSCRIPTION_ID`, or a
  managed identity. Inventory covers locations, resource groups, VNets and
  subnets. The artifact is a managed image or a Compute Gallery version.
- On both clouds, WinRM is bootstrapped through user data or a custom
  script extension instead of an answer file. The OS settings, update and
  post-install steps work unchanged.

## Smaller follow-ups (any target)

- **Script library.** A catalog kind (`scripts/<id>.yaml`) for reusable
  post-install and post-deploy scripts the wizard can pick from, next to
  the free-form script box.
- **Product keys and editions.** A sealed `product_key` variable, so
  `windows-11` can offer Enterprise and Education with a matching key, and
  Server can use retail or MAK keys.
- **Build presets.** Save a filled-in wizard (image, settings, apps,
  script) as a named preset, and run it on a schedule to keep templates
  patched.
- **Template versioning.** Keep the last N templates per preset, and mark
  one as current for deploy.
