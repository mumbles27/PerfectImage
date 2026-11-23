build {
  name    = "perfectimage"
  sources = ["source.proxmox-iso.image"]

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/base.ps1"]
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # @perfectimage:apps

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/cleanup.ps1"]
  }

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/sysprep.ps1"]
  }
}
