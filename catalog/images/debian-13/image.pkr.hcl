# Debian 13 (trixie) for Proxmox VE.
#
# Proxmox credentials are never set here: the hashicorp/proxmox plugin reads
# PROXMOX_URL, PROXMOX_USERNAME and PROXMOX_TOKEN from the environment.
# PerfectImage writes every other variable to a 0600 *.auto.pkrvars.hcl file
# and passes build_password as PKR_VAR_build_password.

packer {
  required_plugins {
    proxmox = {
      source  = "github.com/hashicorp/proxmox"
      version = "~> 1.2"
    }
  }
}

variable "proxmox_node" {
  type        = string
  description = "Proxmox node that runs the build VM."
}

variable "proxmox_insecure" {
  type    = bool
  default = false
}

variable "vm_id" {
  type        = number
  default     = 0
  description = "VMID of the template; 0 picks the next free ID."
}

variable "template_name" {
  type    = string
  default = "debian-13"
}

variable "template_description" {
  type    = string
  default = "Debian 13 (trixie) netinst built by PerfectImage"
}

variable "tags" {
  type    = string
  default = "perfectimage;linux;debian"
}

variable "cores" {
  type    = number
  default = 2
}

variable "memory" {
  type    = number
  default = 4096
}

variable "disk_size" {
  type    = string
  default = "16G"
}

variable "storage_pool" {
  type    = string
  default = "local-lvm"
}

variable "bridge" {
  type    = string
  default = "vmbr0"
}

variable "iso_url" {
  type    = string
  default = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.8.0-amd64-netinst.iso"
}

variable "iso_checksum" {
  type    = string
  default = "file:https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS"
}

variable "iso_file" {
  type        = string
  default     = ""
  description = "ISO already on Proxmox storage (e.g. local:iso/image.iso); overrides iso_url."
}

variable "iso_storage_pool" {
  type    = string
  default = "local"
}

variable "build_username" {
  type    = string
  default = "packer"
}

variable "build_password" {
  type        = string
  sensitive   = true
  description = "Temporary password of the build user; random per build."
}

source "proxmox-iso" "image" {
  node                     = var.proxmox_node
  insecure_skip_tls_verify = var.proxmox_insecure
  task_timeout             = "15m"

  vm_id                = var.vm_id
  vm_name              = "pi-build-${var.template_name}"
  template_name        = var.template_name
  template_description = var.template_description
  tags                 = var.tags

  os              = "l26"
  bios            = "ovmf"
  machine         = "q35"
  cpu_type        = "x86-64-v2-AES"
  cores           = var.cores
  memory          = var.memory
  scsi_controller = "virtio-scsi-single"
  qemu_agent      = true

  efi_config {
    efi_storage_pool  = var.storage_pool
    efi_type          = "4m"
    pre_enrolled_keys = true
  }

  disks {
    type         = "scsi"
    disk_size    = var.disk_size
    storage_pool = var.storage_pool
    format       = "raw"
    io_thread    = true
    discard      = true
  }

  network_adapters {
    model  = "virtio"
    bridge = var.bridge
  }

  boot_iso {
    type             = "sata"
    iso_file         = var.iso_file != "" ? var.iso_file : null
    iso_url          = var.iso_file == "" ? var.iso_url : null
    iso_checksum     = var.iso_file == "" ? var.iso_checksum : null
    iso_storage_pool = var.iso_storage_pool
    unmount          = true
  }

  cloud_init              = true
  cloud_init_storage_pool = var.storage_pool

  http_content = {
    "/preseed.cfg" = templatefile("${path.root}/http/preseed.pkrtpl", {
      username = var.build_username
      password = var.build_password
    })
  }

  boot_wait = "10s"
  boot_command = [
    "<wait3s>c<wait3s>",
    "linux /install.amd/vmlinuz auto=true priority=critical url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg interface=auto hostname=debian domain=local ---<enter><wait>",
    "initrd /install.amd/initrd.gz<enter><wait>",
    "boot<enter>"
  ]

  communicator           = "ssh"
  ssh_username           = var.build_username
  ssh_password           = var.build_password
  ssh_timeout            = "60m"
  ssh_handshake_attempts = 200
}
