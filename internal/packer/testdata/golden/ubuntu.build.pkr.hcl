build {
  name    = "perfectimage"
  sources = ["source.proxmox-iso.image"]

  provisioner "shell" {
    execute_command = "{{ .Vars }} sudo -E bash -eu '{{ .Path }}'"
    scripts         = ["${path.root}/scripts/base.sh"]
  }

  # BEGIN PerfectImage apps (generated: 4 step(s))
  provisioner "shell" {
    # curl (curl)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/01-curl.sh"
  }
  provisioner "shell" {
    # htop (htop)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/02-htop.sh"
  }
  provisioner "shell" {
    # Git (git)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/03-git.sh"
  }
  provisioner "shell" {
    # Docker (docker)
    execute_command = "{{ .Vars }} sudo -E bash '{{ .Path }}'"
    script          = "${path.root}/perfectimage/apps/04-docker.sh"
  }
  provisioner "shell" {
    # reboot required by docker
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
