#!/usr/bin/env bash
# Generalize the VM before it becomes a template.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "==> Cleaning packages"
apt-get -y -q autoremove --purge
apt-get -y -q clean
rm -rf /var/lib/apt/lists/*

echo "==> Resetting cloud-init"
cloud-init clean --logs --seed

echo "==> Removing SSH host keys (regenerated on first boot)"
rm -f /etc/ssh/ssh_host_*
# Debian only regenerates host keys on boot if a unit does it.
cat >/etc/systemd/system/pi-ssh-hostkeys.service <<'UNIT'
[Unit]
Description=Regenerate SSH host keys if missing
Before=ssh.service
ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target
UNIT
systemctl enable pi-ssh-hostkeys.service >/dev/null 2>&1 || true

echo "==> Cleaning machine-id"
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "==> Clearing logs and temporary files"
find /var/log -type f -exec truncate -s 0 {} +
rm -rf /tmp/* /var/tmp/*

echo "==> Locking the build user ${BUILD_USERNAME:-packer}"
rm -f /etc/sudoers.d/99-pi-build /etc/sudoers.d/90-cloud-init-users
if id "${BUILD_USERNAME:-packer}" >/dev/null 2>&1; then
  passwd -l "${BUILD_USERNAME:-packer}"
  usermod -e 1 "${BUILD_USERNAME:-packer}"
fi
rm -f /root/.bash_history "/home/${BUILD_USERNAME:-packer}/.bash_history"
sync
