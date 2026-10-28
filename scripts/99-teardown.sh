#!/usr/bin/env bash
# Tear everything down so nothing keeps costing money.
# The vault stays soft-deleted for 7 days (purge protection) - that costs nothing and is the point.
source "$(dirname "$0")/lib.sh"
require_login

read -r -p "Delete resource group $RG and all lab resources? Type the RG name to confirm: " answer
[[ "$answer" == "$RG" ]] || { echo "aborted"; exit 1; }

log "Policy assignments"
for a in $(azq policy assignment list --scope "$RG_ID" --query "[?starts_with(name,'zt-')].name" -o tsv); do
  az policy assignment delete --name "$a" --scope "$RG_ID" && pass "removed $a"
done

log "Subscription Activity Log export"
az monitor diagnostic-settings subscription delete --name sc500-activity-to-law --yes 2>/dev/null \
  && pass "removed sc500-activity-to-law" || warn "not found"

log "GitHub OIDC app"
if [[ -f "$STATE/oidc.env" ]]; then
  source "$STATE/oidc.env"
  az ad app delete --id "$GH_APP_ID" && pass "deleted app registration (its role assignments become orphaned and are removed with the RG)"
fi

log "Resource group (VM, disk, vault, workspace, identity, alerts)"
az group delete -n "$RG" --yes && pass "deleted $RG"

log "Soft-deleted vaults (cannot be purged until retention ends - by design)"
az keyvault list-deleted --query "[].{name:name, scheduledPurge:properties.scheduledPurgeDate}" -o table

rm -f "$STATE/env.sh" "$STATE/params.json" "$STATE/suffix" "$STATE/oidc.env"
echo "Next deploy gets a new suffix (the old vault name stays reserved until its purge date)."
