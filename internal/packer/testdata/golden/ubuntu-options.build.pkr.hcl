build {
  name    = "perfectimage"
  sources = ["source.proxmox-iso.image"]

  provisioner "shell" {
    execute_command = "{{ .Vars }} sudo -E bash -eu '{{ .Path }}'"
    scripts         = ["${path.root}/scripts/base.sh"]
  }

  # BEGIN PerfectImage apps (generated: 6 step(s))
  provisioner "shell" {
    # OS settings (_os-settings)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/01-_os-settings.sh"
  }
  provisioner "shell" {
    # OS updates (_os-updates)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/02-_os-updates.sh"
  }
  provisioner "shell" {
    # reboot required by _os-updates
    execute_command   = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    inline            = ["systemctl reboot"]
    expect_disconnect = true
  }
  provisioner "shell" {
    pause_before = "60s"
    inline       = ["echo reconnected after reboot"]
  }
  provisioner "shell" {
    # curl (curl)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/03-curl.sh"
  }
  provisioner "shell" {
    # htop (htop)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/04-htop.sh"
  }
  provisioner "shell" {
    # Git (git)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/05-git.sh"
  }
  provisioner "shell" {
    # Post-install script (_post-install)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/06-_post-install.sh"
  }
  provisioner "shell" {
    # reboot required by _post-install
    execute_command   = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    inline            = ["systemctl reboot"]
    expect_disconnect = true
  }
  provisioner "shell" {
    pause_before = "60s"
    inline       = ["echo reconnected after reboot"]
  }
  # END PerfectImage apps

  provisioner "shell" {
    execute_command = "{{ .Vars }} sudo -E bash -eu '{{ .Path }}'"
    environment_vars = [
      "BUILD_USERNAME=${var.build_username}",
    ]
    scripts = ["${path.root}/scripts/cleanup.sh"]
  }
}
