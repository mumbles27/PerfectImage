build {
  name    = "perfectimage"
  sources = ["source.proxmox-iso.image"]

  provisioner "shell" {
    execute_command = "{{ .Vars }} sudo -E bash -eu '{{ .Path }}'"
    scripts         = ["${path.root}/scripts/base.sh"]
  }

  # @perfectimage:apps

  provisioner "shell" {
    execute_command = "{{ .Vars }} sudo -E bash -eu '{{ .Path }}'"
    environment_vars = [
      "BUILD_USERNAME=${var.build_username}",
    ]
    scripts = ["${path.root}/scripts/cleanup.sh"]
  }
}
