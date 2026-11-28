#!/usr/bin/env bash
# Base provisioning for Ubuntu: wait for cloud-init, update, guest agent.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "==> Waiting for cloud-init to finish"
cloud-init status --wait >/dev/null 2>&1 || true

echo "==> Updating packages"
apt-get update -q
apt-get -y -q -o Dpkg::Options::=--force-confold dist-upgrade
apt-get -y -q install qemu-guest-agent cloud-init cloud-guest-utils curl ca-certificates gnupg
systemctl enable --now qemu-guest-agent

echo "==> Configuring cloud-init for Proxmox (NoCloud/ConfigDrive)"
cat >/etc/cloud/cloud.cfg.d/99-pve.cfg <<'CFG'
datasource_list: [NoCloud, ConfigDrive]
CFG
# The installer's network config stays until cleanup.sh: provisioners that
# reboot the guest (OS updates, apps with reboot_required) need DHCP to come
# back so Packer can reconnect over SSH.
