#!/usr/bin/env bash
# Step 1: deploy the lab.
#   ./scripts/01-deploy.sh                                   # vault + identity + logging (free)
#   DEPLOY_WORKLOAD=true ALERT_EMAIL=me@x.com ./scripts/01-deploy.sh   # + probe VM + alerts
source "$(dirname "$0")/lib.sh"
require_login

: "${DEPLOY_WORKLOAD:=false}"
: "${ALERT_EMAIL:=}"
: "${ARC_PRINCIPAL_ID:=}"   # set after local-lab/arc-onboard.sh (on-prem VirtualBox server)

# One suffix per lab, remembered between runs (vault names are global and soft-delete keeps them for 7 days).
if [[ -z "${SUFFIX:-}" ]]; then
  if [[ -f "$STATE/suffix" ]]; then SUFFIX="$(cat "$STATE/suffix")"
  else SUFFIX="zt$(date +%m%d)$((RANDOM % 1000))"; fi
fi
echo "$SUFFIX" > "$STATE/suffix"

log "Who am I / where am I"
ADMIN_OID="$(azq ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
MY_IP="$(curl -s https://api.ipify.org || true)"
echo "suffix=$SUFFIX rg=$RG location=$LOCATION workload=$DEPLOY_WORKLOAD"
[[ -n "$ADMIN_OID" ]] && echo "admin object id found" || warn "no user object id - admin will not get Secrets Officer"
[[ -n "$MY_IP" ]] && echo "public IP $MY_IP will be allowed through the vault firewall" || warn "could not detect public IP"

log "Resource group"
az group create -n "$RG" -l "$LOCATION" \
  --tags project=azure-iam-zero-trust-lab environment=lab >/dev/null
pass "$RG"

SSH_PUB=""
if [[ "$DEPLOY_WORKLOAD" == "true" ]]; then
  # Throwaway key: the VM has no inbound path at all, so this key is never actually used to log in.
  [[ -f "$STATE/vm_key" ]] || ssh-keygen -t ed25519 -N "" -C "sc500-lab" -f "$STATE/vm_key" -q
  SSH_PUB="$(cat "$STATE/vm_key.pub")"
fi

IPS="[]"; [[ -n "$MY_IP" ]] && IPS="[\"$MY_IP\"]"
cat > "$STATE/params.json" <<EOF
{
  "\$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "suffix":           { "value": "$SUFFIX" },
    "adminPrincipalId": { "value": "$ADMIN_OID" },
    "allowedIpRanges":  { "value": $IPS },
    "deployWorkload":   { "value": $DEPLOY_WORKLOAD },
    "vmSshPublicKey":   { "value": "$SSH_PUB" },
    "alertEmail":       { "value": "$ALERT_EMAIL" },
    "arcPrincipalId":   { "value": "$ARC_PRINCIPAL_ID" }
  }
}
EOF

log "What-if (review this: it is your change-control record)"
az deployment group what-if -g "$RG" -n "$DEPLOYMENT" -f infra/main.bicep -p @"$STATE/params.json" \
  --result-format ResourceIdOnly | tee "$STATE/what-if.txt"

log "Deploy main.bicep"
az deployment group create -g "$RG" -n "$DEPLOYMENT" -f infra/main.bicep -p @"$STATE/params.json" \
  --query properties.provisioningState -o tsv | tr -d '\r'

az deployment group show -g "$RG" -n "$DEPLOYMENT" --query properties.outputs -o json \
  | "$PY" -c 'import json,sys; [print("export OUT_%s=\"%s\"" % (k, v["value"])) for k, v in json.load(sys.stdin).items()]' \
  | tr -d '\r' > "$STATE/env.sh"
{ echo "export ADMIN_OID=\"$ADMIN_OID\""; echo "export MY_IP=\"$MY_IP\""; } >> "$STATE/env.sh"
load_outputs
pass "vault $OUT_keyVaultName, identity $(basename "$OUT_managedIdentityId")"

log "Send subscription Activity Log to the workspace (free ingestion)"
az deployment sub create -l "$LOCATION" -n sc500-activity-log -f infra/activity-log.bicep \
  -p workspaceId="$OUT_workspaceId" --query properties.provisioningState -o tsv | tr -d '\r'

echo
echo "Next: wait ~5 minutes for RBAC to propagate, then run ./scripts/02-verify.sh"
