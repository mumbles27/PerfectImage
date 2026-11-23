#!/usr/bin/env bash
# Generalize the VM before it becomes a template.
set -euo pipefail

echo "==> Cleaning packages"
dnf -y -q clean all
rm -rf /var/cache/dnf/*

echo "==> Resetting cloud-init"
cloud-init clean --logs --seed

echo "==> Removing SSH host keys (regenerated on first boot by sshd-keygen)"
rm -f /etc/ssh/ssh_host_*

echo "==> Removing NetworkManager connection files (may carry MAC addresses)"
rm -f /etc/NetworkManager/system-connections/*
rm -f /etc/NetworkManager/conf.d/*-installer.conf
rm -f /etc/udev/rules.d/70-persistent-net.rules

echo "==> Cleaning machine-id"
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "==> Clearing logs and temporary files"
find /var/log -type f -exec truncate -s 0 {} +
rm -rf /tmp/* /var/tmp/*

echo "==> Locking the build user ${BUILD_USERNAME:-packer}"
rm -f /etc/sudoers.d/99-pi-build
if id "${BUILD_USERNAME:-packer}" >/dev/null 2>&1; then
  passwd -l "${BUILD_USERNAME:-packer}"
  usermod -e 1 "${BUILD_USERNAME:-packer}"
fi
rm -f /root/.bash_history "/home/${BUILD_USERNAME:-packer}/.bash_history"
sync
