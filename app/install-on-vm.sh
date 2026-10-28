#!/usr/bin/env bash
# Runs ON the VM (as root, via sudo). Installs zt-app as a sandboxed systemd service.
#   sudo bash install-on-vm.sh <vault-name> [secret-name] [vuln-ssrf 0|1]
set -euo pipefail
VAULT="${1:?vault name required}"; SECRET="${2:-app-db-password}"; VULN="${3:-0}"
SRC="$(cd "$(dirname "$0")" && pwd)"

getent group himds >/dev/null || { echo "Azure Arc agent not installed (no 'himds' group). Run local-lab/arc-onboard.sh first."; exit 1; }

# Dedicated, non-login service account (AC-2): no shell, no home, no sudo.
id ztapp >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ztapp
usermod -aG himds ztapp

install -d -m 0755 /opt/zt-app
install -m 0644 "$SRC/zt_app.py" /opt/zt-app/zt_app.py
install -d -m 0750 -o root -g ztapp /etc/zt-app
cat > /etc/zt-app/app.env <<EOF
# Non-secret configuration only. There is intentionally no credential in this file.
ZT_VAULT_NAME=$VAULT
ZT_SECRET_NAME=$SECRET
ZT_PORT=8080
ZT_VULN_SSRF=$VULN
EOF
chmod 0640 /etc/zt-app/app.env; chown root:ztapp /etc/zt-app/app.env
install -m 0644 "$SRC/zt-app.service" /etc/systemd/system/zt-app.service

systemctl daemon-reload
systemctl enable --now zt-app
systemctl restart zt-app
sleep 2
systemctl --no-pager --lines=5 status zt-app
echo "--- sandbox score (lower is better):"
systemd-analyze security zt-app --no-pager | tail -1
