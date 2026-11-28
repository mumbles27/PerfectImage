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

echo "==> Handing networking to cloud-init (Proxmox ipconfig0 / DHCP on clones)"
# Done here, not in base.sh: the build VM must keep its network across the
# reboots of earlier provisioners.
rm -f /etc/cloud/cloud.cfg.d/99-installer.cfg /etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg
rm -f /etc/netplan/00-installer-config.yaml /etc/netplan/50-cloud-init.yaml

echo "==> Removing SSH host keys (regenerated on first boot)"
rm -f /etc/ssh/ssh_host_*

echo "==> Cleaning machine-id"
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "==> Clearing logs and temporary files"
find /var/log -type f -exec truncate -s 0 {} +
rm -rf /tmp/* /var/tmp/*

echo "==> Locking the build user ${BUILD_USERNAME:-packer}"
if id "${BUILD_USERNAME:-packer}" >/dev/null 2>&1; then
  passwd -l "${BUILD_USERNAME:-packer}"
  usermod -e 1 "${BUILD_USERNAME:-packer}"
fi
rm -f /etc/sudoers.d/90-cloud-init-users
rm -f /root/.bash_history "/home/${BUILD_USERNAME:-packer}/.bash_history"
sync
