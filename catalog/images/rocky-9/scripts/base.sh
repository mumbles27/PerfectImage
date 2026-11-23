#!/usr/bin/env bash
# Base provisioning for Rocky Linux 9: wait for cloud-init, update, guest agent.
set -euo pipefail

echo "==> Waiting for cloud-init to finish"
cloud-init status --wait >/dev/null 2>&1 || true

echo "==> Updating packages"
dnf -y -q upgrade --refresh
dnf -y -q install qemu-guest-agent cloud-init cloud-utils-growpart curl ca-certificates
systemctl enable --now qemu-guest-agent || true

echo "==> Configuring cloud-init for Proxmox (NoCloud/ConfigDrive)"
cat >/etc/cloud/cloud.cfg.d/99-pve.cfg <<'CFG'
datasource_list: [NoCloud, ConfigDrive]
CFG
systemctl enable cloud-init-local cloud-init cloud-config cloud-final >/dev/null 2>&1 || true
