# Windows 11 Pro for Proxmox VE.
#
# Proxmox credentials are never set here: the hashicorp/proxmox plugin reads
# PROXMOX_URL, PROXMOX_USERNAME and PROXMOX_TOKEN from the environment.
# PerfectImage writes every other variable to a 0600 *.auto.pkrvars.hcl file
# and passes build_password as PKR_VAR_build_password.
#
# Install media is user-supplied: upload a Windows ISO and the virtio-win ISO
# to Proxmox storage and set iso_file / virtio_iso_file.
# The answer file and scripts are delivered on a generated CD (cd_content),
# which needs xorriso (or mkisofs/genisoimage/oscdimg) on the Packer host.

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
  default = "windows-11"
}

variable "template_description" {
  type    = string
  default = "Windows 11 Pro built by PerfectImage"
}

variable "tags" {
  type    = string
  default = "perfectimage;windows;windows-11"
}

variable "cores" {
  type    = number
  default = 4
}

variable "memory" {
  type    = number
  default = 8192
}

variable "disk_size" {
  type    = string
  default = "80G"
}

variable "storage_pool" {
  type    = string
  default = "local-lvm"
}

variable "bridge" {
  type    = string
  default = "vmbr0"
}

# Unused for Windows (the ISO is user-supplied); declared for the common contract.
variable "iso_url" {
  type    = string
  default = ""
}

variable "iso_checksum" {
  type    = string
  default = ""
}

variable "iso_file" {
  type        = string
  default     = ""
  description = "Windows install ISO on Proxmox storage (e.g. local:iso/windows-11.iso)."
}

variable "iso_storage_pool" {
  type    = string
  default = "local"
}

variable "virtio_iso_file" {
  type        = string
  default     = "local:iso/virtio-win.iso"
  description = "virtio-win driver ISO on Proxmox storage."
}

variable "windows_image_name" {
  type        = string
  default     = "Windows 11 Pro"
  description = "Edition name inside install.wim (/IMAGE/NAME)."
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

  vm_id                = var.vm_id
  vm_name              = "pi-build-${var.template_name}"
  template_name        = var.template_name
  template_description = var.template_description
  tags                 = var.tags

  os              = "win11"
  bios            = "ovmf"
  machine         = "q35"
  cpu_type        = "host"
  cores           = var.cores
  memory          = var.memory
  scsi_controller = "virtio-scsi-single"
  qemu_agent      = true

  efi_config {
    efi_storage_pool  = var.storage_pool
    efi_type          = "4m"
    pre_enrolled_keys = true
  }

  tpm_config {
    tpm_storage_pool = var.storage_pool
    tpm_version      = "v2.0"
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
    type     = "sata"
    iso_file = var.iso_file
    unmount  = true
  }

  additional_iso_files {
    type     = "sata"
    iso_file = var.virtio_iso_file
    unmount  = true
  }

  additional_iso_files {
    type             = "sata"
    cd_label         = "PIUNATTEND"
    iso_storage_pool = var.iso_storage_pool
    unmount          = true
    cd_files = [
      "${path.root}/scripts/virtio.ps1",
      "${path.root}/scripts/winrm.ps1",
    ]
    cd_content = {
      "autounattend.xml" = templatefile("${path.root}/answer/autounattend.pkrtpl.xml", {
        username    = var.build_username
        password    = var.build_password
        image_name  = var.windows_image_name
        product_key = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
        virtio_dir  = "w11"
      })
    }
  }

  boot_wait = "3s"
  boot_command = [
    "<spacebar><wait><spacebar><wait><spacebar>"
  ]

  communicator   = "winrm"
  winrm_username = var.build_username
  winrm_password = var.build_password
  winrm_use_ssl  = true
  winrm_insecure = true
  winrm_port     = 5986
  winrm_timeout  = "4h"
}
