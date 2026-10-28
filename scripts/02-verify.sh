#!/usr/bin/env bash
# Step 2: prove the controls work - positive AND negative tests.
# Output is saved to .state/verify.txt and later copied (redacted) into evidence/.
source "$(dirname "$0")/lib.sh"
require_login
load_outputs
exec > >(tee "$STATE/verify.txt") 2>&1

APP_SCOPE_SUFFIX="/providers/Microsoft.KeyVault/vaults/$OUT_keyVaultName/secrets/$OUT_appSecretName"

log "C1  Workload identity has exactly one role assignment, scoped to one secret  (AC-6, AC-3)"
az role assignment list --assignee "$OUT_identityPrincipalId" --all \
  --query "[].{role:roleDefinitionName, scope:scope}" -o json > "$STATE/mi-roles.json"
count="$(azq role assignment list --assignee "$OUT_identityPrincipalId" --all --query "length(@)" -o tsv)"
role="$(azq role assignment list --assignee "$OUT_identityPrincipalId" --all --query "[0].roleDefinitionName" -o tsv)"
scope="$(azq role assignment list --assignee "$OUT_identityPrincipalId" --all --query "[0].scope" -o tsv)"
[[ "$count" == "1" ]] && pass "1 assignment" || fail "expected 1 assignment, found $count"
[[ "$role" == "Key Vault Secrets User" ]] && pass "role = Key Vault Secrets User" || fail "role = $role"
[[ "$scope" == *"$APP_SCOPE_SUFFIX" ]] && pass "scope = single secret ($OUT_appSecretName)" || fail "scope = $scope"

log "C2  No privileged roles anywhere for the workload  (AC-6, AC-6(10))"
priv="$(azq role assignment list --assignee "$OUT_identityPrincipalId" --all \
  --query "[?contains(['Owner','Contributor','User Access Administrator','Role Based Access Control Administrator','Key Vault Administrator','Key Vault Secrets Officer'], roleDefinitionName)] | length(@)" -o tsv)"
[[ "$priv" == "0" ]] && pass "no Owner/Contributor/UAA/RBAC Admin/KV Admin/Officer" || fail "$priv privileged assignment(s)"

log "C3  Key Vault hardening  (SC-7, SC-28, CP-10, CM-7)"
az keyvault show -n "$OUT_keyVaultName" -o json > "$STATE/keyvault.json"
kv() { azq keyvault show -n "$OUT_keyVaultName" --query "$1" -o tsv; }
[[ "$(kv properties.enableRbacAuthorization)" == "true" ]] && pass "RBAC permission model" || fail "access policies in use"
[[ "$(kv properties.enableSoftDelete)" == "true" ]] && pass "soft delete" || fail "soft delete off"
[[ "$(kv properties.enablePurgeProtection)" == "true" ]] && pass "purge protection" || fail "purge protection off"
[[ "$(kv properties.networkAcls.defaultAction)" == "Deny" ]] && pass "firewall default = Deny" || fail "firewall default allows"
[[ "$(kv properties.networkAcls.bypass)" == "None" ]] && pass "no trusted-service bypass" || warn "bypass = $(kv properties.networkAcls.bypass)"
[[ "$(kv "length(properties.accessPolicies)")" == "0" ]] && pass "no legacy access policies" || fail "legacy access policies present"
for f in enabledForDeployment enabledForTemplateDeployment enabledForDiskEncryption; do
  [[ "$(kv "properties.$f")" != "true" ]] && pass "$f disabled" || fail "$f enabled"
done

log "C4  Secrets expire  (IA-5(1)-style rotation hygiene)"
for s in "$OUT_appSecretName" "$OUT_decoySecretName"; do
  exp="$(azq keyvault secret show --vault-name "$OUT_keyVaultName" -n "$s" --query attributes.expires -o tsv 2>/dev/null || echo "")"
  if [[ -n "$exp" ]]; then pass "$s expires $exp"
  else warn "$s: could not read metadata (firewall/RBAC propagation?) - retry in a few minutes"; fi
done

log "C5  Audit logging is on  (AU-2, AU-12)"
az monitor diagnostic-settings list --resource "$OUT_keyVaultId" -o json > "$STATE/kv-diagnostics.json"
audit="$(azq monitor diagnostic-settings list --resource "$OUT_keyVaultId" \
  --query "length([].logs[?category=='AuditEvent' && enabled][])" -o tsv)"
[[ "$audit" -ge 1 ]] && pass "Key Vault AuditEvent -> Log Analytics" || fail "AuditEvent not exported"
az monitor diagnostic-settings subscription list -o json > "$STATE/sub-diagnostics.json" 2>/dev/null || true
grep -q "sc500-activity-to-law" "$STATE/sub-diagnostics.json" && pass "Activity Log -> Log Analytics" \
  || fail "subscription Activity Log not exported"

log "C6  Network: firewall blocks callers outside the allow-list  (SC-7)"
echo "Manual check (Cloud Shell has a different IP than your laptop):"
echo "  az keyvault secret show --vault-name $OUT_keyVaultName -n $OUT_appSecretName   # expect ForbiddenByFirewall"

if [[ -n "${OUT_vmName:-}" ]]; then
  log "C7  Probe VM has no public IP, no inbound  (SC-7, CM-7)"
  pips="$(azq vm list-ip-addresses -g "$RG" -n "$OUT_vmName" --query "length([].virtualMachine.network.publicIpAddresses[])" -o tsv)"
  [[ "$pips" == "0" ]] && pass "no public IP" || fail "$pips public IP(s)"
  pwd_auth="$(azq vm show -g "$RG" -n "$OUT_vmName" --query osProfile.linuxConfiguration.disablePasswordAuthentication -o tsv)"
  [[ "$pwd_auth" == "true" ]] && pass "password auth disabled" || fail "password auth enabled"

  log "C8  Workload probes from inside the VM (one run-command, ~60s)  (AC-3, AC-6, IA-9)"
  az vm run-command invoke -g "$RG" -n "$OUT_vmName" --command-id RunShellScript \
    --scripts @scripts/vm/probe.sh \
    --parameters "$OUT_identityClientId" "$OUT_keyVaultName" "$SUB_ID" "$OUT_appSecretName" "$OUT_decoySecretName" \
    --query "value[0].message" -o tsv | tr -d '\r' > "$STATE/probes.txt"
  grep '^PROBE' "$STATE/probes.txt" || { fail "no probe output"; cat "$STATE/probes.txt"; }

  expect() {  # probe-name expected-http [expected-text] description
    local line; line="$(grep "^PROBE $1 " "$STATE/probes.txt" || true)"
    if [[ "$line" == *"http=$2"* && "$line" == *"${3:-}"* ]]; then pass "$4"; else fail "$4  ->  ${line:-missing}"; fi
  }
  expect imds_token        200 ""                "identity gets a token from IMDS (no stored credential)"
  expect read_app_secret   200 "len="            "CAN read $OUT_appSecretName"
  expect read_decoy_secret 403 "ForbiddenByRbac" "CANNOT read $OUT_decoySecretName"
  expect list_secrets      403 ""                "CANNOT enumerate secrets"
  expect write_secret      403 ""                "CANNOT overwrite a secret"
  expect delete_secret     403 ""                "CANNOT delete a secret"
  expect arm_list_rgs      200 "items=0"            "sees ZERO resource groups (ARM filters lists)"
  expect arm_read_rg       403 "AuthorizationFailed" "CANNOT read the resource group"
  expect arm_escalate_owner 403 "AuthorizationFailed" "CANNOT grant itself Owner"
  expect graph_list_users  403 ""                "CANNOT read the directory"
  expect internet_egress   000 ""                "CANNOT reach the internet"
else
  warn "No probe VM (DEPLOY_WORKLOAD=false). Data-plane tests C7/C8 skipped."
fi

summary
