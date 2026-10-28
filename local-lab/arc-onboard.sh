#!/usr/bin/env bash
# Runs ON the VirtualBox VM (sudo). Turns the on-prem server into an Azure Arc-enabled server,
# which gives it a system-assigned managed identity - the off-Azure equivalent of a VM's MI.
#
#   sudo bash arc-onboard.sh <resource-group> <subscription-id> <tenant-id> [location]
#
# Onboarding uses device-code login (you approve it with MFA in a browser), so no service-principal
# secret is ever created or stored on the box.
set -euo pipefail
RG="${1:?resource group}"; SUB="${2:?subscription id}"; TENANT="${3:?tenant id}"; LOCATION="${4:-eastus}"

if ! command -v azcmagent >/dev/null; then
  echo "==> Downloading the Connected Machine agent installer from Microsoft"
  curl -sSfL -o /tmp/install_linux_azcmagent.sh https://gbl.his.arc.azure.com/azcmagent-linux
  echo "installer sha256: $(sha256sum /tmp/install_linux_azcmagent.sh | cut -d' ' -f1)   # record in the lab journal"
  bash /tmp/install_linux_azcmagent.sh
fi
azcmagent version

echo "==> Connecting to Azure (device code - approve with MFA in your browser)"
azcmagent connect \
  --resource-group "$RG" --subscription-id "$SUB" --tenant-id "$TENANT" --location "$LOCATION" \
  --use-device-code \
  --tags "project=azure-iam-zero-trust-lab,environment=lab,hosting=on-prem-virtualbox"

echo "==> Least functionality (CM-7): monitor mode = no remote extensions, no run-command,"
echo "    no guest configuration, no SSH-over-Arc. Azure can see the box but cannot drive it."
azcmagent config set config.mode monitor

echo "==> auditd: record every access to the Arc token key files (AU-12)"
echo "-w /var/opt/azcmagent/tokens -p r -k arc_token_read" > /etc/audit/rules.d/zt-arc.rules
augenrules --load && auditctl -l | grep arc_token_read

echo "==> Who may ask for a token? Only root and members of 'himds':"
getent group himds
ls -ld /var/opt/azcmagent/tokens
azcmagent show | grep -E "Resource Name|Agent Status|Resource Group|Agent Version"
azcmagent config list | grep -E "config.mode|incomingconnections|extensions.allowlist|guestconfiguration" || true
