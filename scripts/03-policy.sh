#!/usr/bin/env bash
# Step 3: continuous compliance with Azure Policy (free) + Defender for Cloud foundational CSPM (free).
#   ./scripts/03-policy.sh assign     # assign built-in audit policies to the lab RG
#   ./scripts/03-policy.sh report     # ~30 min later: compliance + Defender recommendations
source "$(dirname "$0")/lib.sh"
require_login

# Built-in definitions, looked up by display name so no GUIDs are hard-coded.
# All are Audit / AuditIfNotExists: they report, they do not block the lab.
POLICIES=(
  "Azure Key Vault should use RBAC permission model"
  "Key vaults should have deletion protection enabled"
  "Key vaults should have soft delete enabled"
  "Key Vault secrets should have an expiration date"
  "Secrets should have content type set"
  "Resource logs in Key Vault should be enabled"
  "Azure Key Vault should have firewall enabled or public network access disabled"
  "Azure Key Vaults should use private link"
  "Audit usage of custom RBAC roles"
  "Machines should be configured to periodically check for missing system updates"
)

assign() {
  log "Caching built-in policy definitions (one call, ~15s)"
  az policy definition list --query "[?policyType=='BuiltIn'].[name, displayName]" -o tsv \
    | tr -d '\r' > "$STATE/builtin-policies.tsv"
  for name in "${POLICIES[@]}"; do
    id="$(awk -F'\t' -v n="$name" '$2==n {print $1; exit}' "$STATE/builtin-policies.tsv")"
    if [[ -z "$id" ]]; then
      warn "not found (renamed?): $name"
      echo "      search: az policy definition list --query \"[?contains(displayName,'Key Vault')].displayName\" -o tsv"
      continue
    fi
    az policy assignment create --name "zt-${id:0:8}" --display-name "[ZT Lab] $name" \
      --policy "$id" --scope "$RG_ID" >/dev/null
    pass "assigned: $name"
  done
  log "Triggering an on-demand compliance scan (runs in the background)"
  az policy state trigger-scan -g "$RG" --no-wait
  echo "Results appear in ~15-30 minutes. Then run: ./scripts/03-policy.sh report"
}

report() {
  log "Policy compliance for $RG  (CM-6, CA-7)"
  az policy state summarize -g "$RG" \
    --query "{nonCompliantResources:results.nonCompliantResources, nonCompliantPolicies:results.nonCompliantPolicies}" -o table
  az policy state list -g "$RG" --filter "complianceState eq 'NonCompliant'" \
    --query "[].{policy:policyDefinitionName, resource:resourceId}" -o json > "$STATE/policy-noncompliant.json"
  az policy state list -g "$RG" \
    --query "[].{assignment:policyAssignmentName, state:complianceState, resourceType:resourceType}" -o table \
    | tee "$STATE/policy-states.txt"
  echo
  echo "Non-compliant results are FINDINGS. Expected one: 'use private link' (risk accepted - Private"
  echo "Endpoint is not free; compensated by firewall default-deny + service endpoint). See threat-model.md."

  log "Defender for Cloud (foundational CSPM, free) recommendations for $RG  (RA-5)"
  az security assessment list \
    --query "[?contains(id, '/resourceGroups/$RG/') || contains(id, '/resourcegroups/${RG,,}/')].{recommendation:displayName, status:status.code}" \
    -o table 2>/dev/null | tee "$STATE/defender.txt" || warn "Defender assessments not available yet"
}

case "${1:-}" in
  assign) assign ;;
  report) report ;;
  *) echo "usage: $0 assign|report"; exit 2 ;;
esac
