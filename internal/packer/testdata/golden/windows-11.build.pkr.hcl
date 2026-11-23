build {
  name    = "perfectimage"
  sources = ["source.proxmox-iso.image"]

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/base.ps1"]
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # BEGIN PerfectImage apps (generated: 2 step(s))
  provisioner "powershell" {
    # 7-Zip (7zip)
    script = "${path.root}/perfectimage/apps/01-7zip.ps1"
  }
  provisioner "powershell" {
    # Docker (docker)
    script = "${path.root}/perfectimage/apps/02-docker.ps1"
  }
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }
  # END PerfectImage apps

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/cleanup.ps1"]
  }

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/sysprep.ps1"]
  }
}
