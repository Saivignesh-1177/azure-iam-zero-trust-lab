#!/usr/bin/env bash
# Step 4: package REAL outputs into evidence/<date>/, redacted, with SHA-256 hashes.
# Run after 02-verify.sh (and 03-policy.sh report / 05-oidc-github.sh if you did them).
# Never edit the produced files to turn a FAIL into a PASS - see EVIDENCE_POLICY.md.
source "$(dirname "$0")/lib.sh"
require_login
load_outputs
[[ -f "$STATE/oidc.env" ]] && source "$STATE/oidc.env"
[[ -f "$STATE/arc.env" ]] && source "$STATE/arc.env"

DAY="$(date +%Y-%m-%d)"
DIR="evidence/$DAY"
mkdir -p "$DIR"

copy() {  # source dest-name
  if [[ -s "$1" ]]; then cp "$1" "$DIR/$2"; redact "$DIR/$2"; pass "$2"
  else warn "missing $1 - skipped $2"; fi
}

log "EVD-001 Bicep build + lint"
{ az bicep build --file infra/main.bicep --stdout >/dev/null && echo "main.bicep: build OK"
  az bicep lint --file infra/main.bicep && echo "main.bicep: lint OK (0 errors)"
  az bicep version; } > "$STATE/EVD-001.txt" 2>&1 || true
copy "$STATE/EVD-001.txt" EVD-001-bicep-build.txt

log "EVD-002 Automated design tests"
{ "$PY" -m pytest -q 2>&1 || true; } > "$STATE/EVD-002.txt"
copy "$STATE/EVD-002.txt" EVD-002-pytest.txt

log "EVD-003 IaC + secret scanning"
{ if "$PY" -c "import checkov" 2>/dev/null; then
    mkdir -p compiled && az bicep build --file infra/main.bicep --outfile compiled/main.json
    "$PY" -m checkov.main -d compiled --config-file .checkov.yaml --quiet 2>&1 | grep -v WARNI || true   # same as CI
  else echo "checkov not installed (pip install checkov) - CI runs it on every push"; fi
  if command -v gitleaks >/dev/null; then gitleaks detect --source . --redact --no-banner || true
  else echo "gitleaks not installed - CI runs it on every push"; fi; } > "$STATE/EVD-003.txt" 2>&1
copy "$STATE/EVD-003.txt" EVD-003-iac-and-secret-scan.txt

log "EVD-004..006 Azure configuration exports (from 02-verify.sh)"
az role assignment list --assignee "$OUT_identityPrincipalId" --all -o json > "$STATE/mi-roles-full.json"
[[ -n "${ADMIN_OID:-}" ]] && az role assignment list --assignee "$ADMIN_OID" --scope "$OUT_keyVaultId" \
  --query "[].{role:roleDefinitionName, scope:scope}" -o json > "$STATE/admin-roles.json"
copy "$STATE/mi-roles-full.json"     EVD-004-workload-role-assignments.json
copy "$STATE/admin-roles.json"       EVD-004b-admin-vault-roles.json
copy "$STATE/keyvault.json"          EVD-005-keyvault-config.json
copy "$STATE/kv-diagnostics.json"    EVD-006-keyvault-diagnostic-settings.json
copy "$STATE/sub-diagnostics.json"   EVD-006b-activity-log-export.json

log "EVD-007 Verification run (positive + negative tests)"
copy "$STATE/verify.txt" EVD-007-verify-run.txt
copy "$STATE/probes.txt" EVD-007b-workload-probes.txt

log "EVD-013 Hybrid attack scenarios (latest run of attacks/run-attacks.sh)"
# Keep EVERY run, including ones that exposed bugs - failures stay in the record (EVIDENCE_POLICY.md).
for t in "$STATE"/attacks-*.txt; do
  [[ -e "$t" ]] || { warn "no attack run yet"; break; }
  copy "$t" "EVD-013-$(basename "$t")"
done
copy "$STATE/probes-arc.txt" EVD-013b-arc-server-probes.txt

log "EVD-008 Policy compliance + Defender"
copy "$STATE/policy-states.txt"        EVD-008-policy-states.txt
copy "$STATE/policy-noncompliant.json" EVD-008b-policy-noncompliant.json
copy "$STATE/defender.txt"             EVD-012-defender-recommendations.txt

log "EVD-009 KQL hunts (logs take 5-15 minutes to arrive)"
for q in queries/*.kql; do
  name="$(basename "$q" .kql)"
  az monitor log-analytics query -w "$OUT_workspaceCustomerId" --analytics-query "$(cat "$q")" \
    --timespan P7D -o json > "$STATE/kql-$name.json" 2>"$STATE/kql-$name.err" || cat "$STATE/kql-$name.err"
  copy "$STATE/kql-$name.json" "EVD-009-kql-$name.json"
done

log "EVD-010 GitHub OIDC (only if 05-oidc-github.sh was run)"
if [[ -n "${GH_APP_ID:-}" ]]; then
  az ad app federated-credential list --id "$GH_APP_ID" -o json > "$STATE/fic.json"
  az role assignment list --assignee "$GH_SP_OID" --scope "$RG_ID" \
    --query "[].{role:roleDefinitionName, scope:scope, condition:condition}" -o json > "$STATE/gh-roles.json"
  az ad app credential list --id "$GH_APP_ID" -o json > "$STATE/gh-secrets.json"
  copy "$STATE/fic.json"         EVD-010-federated-credential.json
  copy "$STATE/gh-roles.json"    EVD-010b-ci-role-assignments.json
  copy "$STATE/gh-secrets.json"  EVD-010c-ci-client-secrets-should-be-empty.json
  copy "$STATE/gh-deploy-run.txt" EVD-010d-pipeline-deploy-run.txt
else
  warn "GitHub OIDC not configured - skipped"
fi

log "Leak check: no raw identifiers may remain"
leaked=0
for v in "$SUB_ID" "$TENANT_ID" "${OUT_identityPrincipalId:-x}" "${OUT_identityClientId:-x}" "${ADMIN_OID:-x}" "${ARC_PRINCIPAL_ID:-x}" "${MY_IP:-x}"; do
  [[ "$v" == "x" || -z "$v" ]] && continue
  if grep -rIl -- "$v" "$DIR" >/dev/null 2>&1; then leaked=1; fail "identifier still present: ${v:0:6}..."; fi
done
grep -rIlE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----|"value": *"[0-9a-f-]{36}"' "$DIR" && { leaked=1; fail "possible secret material"; }
[[ "$leaked" == "0" ]] && pass "redaction verified"

log "Hashes"
( cd "$DIR" && sha256sum -- * | grep -v SHA256SUMS > SHA256SUMS.txt ) && pass "$DIR/SHA256SUMS.txt"
echo
echo "Now update the Evidence Index table in evidence/README.md with today's results."
summary
