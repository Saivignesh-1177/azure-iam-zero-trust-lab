#!/usr/bin/env bash
# Step 0: tools, login, resource providers, and a budget alarm so the lab stays free.
#   BUDGET_EMAIL=you@example.com ./scripts/00-prereqs.sh
source "$(dirname "$0")/lib.sh"

log "Tooling"
for t in az git curl; do command -v "$t" >/dev/null && pass "$t found" || fail "$t missing"; done
"$PY" --version >/dev/null 2>&1 && pass "python found ($PY)" || fail "python missing"
az bicep version >/dev/null 2>&1 || az bicep install
pass "bicep $(az bicep version 2>/dev/null | tr -d '\r' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
az config set extension.use_dynamic_install=yes_without_prompt >/dev/null 2>&1 || true

log "Azure login"
require_login
pass "subscription $(azq account show --query name -o tsv)"
OFFER="$(azq account show --query "user.type" -o tsv)"
[[ "$OFFER" == "user" ]] && pass "signed in as a user (MFA via Entra security defaults)" \
  || warn "signed in as '$OFFER' - the admin role assignment needs a user object id"

log "Resource providers (registration is free)"
for ns in Microsoft.KeyVault Microsoft.ManagedIdentity Microsoft.OperationalInsights \
          Microsoft.Insights Microsoft.Network Microsoft.Compute Microsoft.PolicyInsights \
          Microsoft.Security Microsoft.HybridCompute Microsoft.GuestConfiguration Microsoft.HybridConnectivity; do
  state="$(azq provider show -n "$ns" --query registrationState -o tsv 2>/dev/null || echo NotRegistered)"
  if [[ "$state" != "Registered" ]]; then az provider register -n "$ns" >/dev/null; warn "$ns registering (takes a minute)"; else pass "$ns"; fi
done

log "Budget guard-rail (email at 50% actual and 100% forecast of a \$5 monthly budget)"
if [[ -n "${BUDGET_EMAIL:-}" ]]; then
  cat > "$STATE/budget.json" <<EOF
{ "properties": {
    "category": "Cost", "amount": 5, "timeGrain": "Monthly",
    "timePeriod": { "startDate": "$(date +%Y-%m-01)T00:00:00Z", "endDate": "2030-12-31T00:00:00Z" },
    "notifications": {
      "actual50":    { "enabled": true, "operator": "GreaterThan", "threshold": 50,  "thresholdType": "Actual",     "contactEmails": ["$BUDGET_EMAIL"] },
      "forecast100": { "enabled": true, "operator": "GreaterThan", "threshold": 100, "thresholdType": "Forecasted", "contactEmails": ["$BUDGET_EMAIL"] }
} } }
EOF
  if az rest --method put \
       --url "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Consumption/budgets/sc500-lab-guardrail?api-version=2023-05-01" \
       --body @"$STATE/budget.json" >/dev/null 2>&1; then
    pass "budget sc500-lab-guardrail created"
  else
    warn "budget API not available for this offer - create one in the portal (Cost Management > Budgets)."
    warn "On a Free Trial the spending limit is your real guard-rail: never remove it."
  fi
else
  warn "BUDGET_EMAIL not set - skipping. Strongly recommended before deploying anything."
fi

summary
