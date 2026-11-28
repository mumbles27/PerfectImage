build {
  name    = "perfectimage"
  sources = ["source.proxmox-iso.image"]

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/base.ps1"]
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # BEGIN PerfectImage apps (generated: 6 step(s))
  provisioner "powershell" {
    # OS settings (_os-settings)
    script = "${path.root}/perfectimage/apps/01-_os-settings.ps1"
  }
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }
  provisioner "powershell" {
    # Windows Update (pass 1 of 3) (_os-updates-1)
    elevated_user     = var.build_username
    elevated_password = var.build_password
    script            = "${path.root}/perfectimage/apps/02-_os-updates-1.ps1"
  }
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }
  provisioner "powershell" {
    # Windows Update (pass 2 of 3) (_os-updates-2)
    elevated_user     = var.build_username
    elevated_password = var.build_password
    script            = "${path.root}/perfectimage/apps/03-_os-updates-2.ps1"
  }
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }
  provisioner "powershell" {
    # Windows Update (pass 3 of 3) (_os-updates-3)
    elevated_user     = var.build_username
    elevated_password = var.build_password
    script            = "${path.root}/perfectimage/apps/04-_os-updates-3.ps1"
  }
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }
  provisioner "powershell" {
    # 7-Zip (7zip)
    script = "${path.root}/perfectimage/apps/05-7zip.ps1"
  }
  provisioner "powershell" {
    # Post-install script (_post-install)
    script = "${path.root}/perfectimage/apps/06-_post-install.ps1"
  }
  # END PerfectImage apps

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/cleanup.ps1"]
  }

  provisioner "powershell" {
    scripts = ["${path.root}/scripts/sysprep.ps1"]
  }
}
