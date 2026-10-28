#!/usr/bin/env bash
# Step 5: secretless CI/CD. GitHub Actions logs in to Azure with OpenID Connect (workload identity
# federation) - there is NO client secret anywhere. Only the "lab" environment of this one repo can
# get a token, and the deployer can only grant the Key Vault Secrets User role (ABAC condition).
#   GITHUB_REPO=owner/repo ./scripts/05-oidc-github.sh
source "$(dirname "$0")/lib.sh"
require_login

: "${GITHUB_REPO:=$(git remote get-url origin | sed -E 's#(https://github.com/|git@github.com:)##; s#\.git$##')}"
APP_NAME="gh-oidc-$(basename "$GITHUB_REPO")"
SUBJECT="repo:${GITHUB_REPO}:environment:lab"
KV_SECRETS_USER="4633458b-17de-408a-b874-0445c86b69e6"

log "App registration + service principal for $GITHUB_REPO"
GH_APP_ID="$(azq ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)"
[[ -z "$GH_APP_ID" ]] && GH_APP_ID="$(azq ad app create --display-name "$APP_NAME" --query appId -o tsv)"
az ad sp show --id "$GH_APP_ID" >/dev/null 2>&1 || az ad sp create --id "$GH_APP_ID" >/dev/null
GH_SP_OID="$(azq ad sp show --id "$GH_APP_ID" --query id -o tsv)"
printf 'export GH_APP_ID="%s"\nexport GH_SP_OID="%s"\n' "$GH_APP_ID" "$GH_SP_OID" > "$STATE/oidc.env"
pass "app $APP_NAME"

log "Federated credential: trust ONLY $SUBJECT"
cat > "$STATE/fic-request.json" <<EOF
{
  "name": "github-lab-environment",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "$SUBJECT",
  "audiences": ["api://AzureADTokenExchange"],
  "description": "GitHub Actions deployments from the protected 'lab' environment only"
}
EOF
if [[ "$(azq ad app federated-credential list --id "$GH_APP_ID" --query "[?name=='github-lab-environment'] | length(@)" -o tsv)" == "0" ]]; then
  az ad app federated-credential create --id "$GH_APP_ID" --parameters @"$STATE/fic-request.json" >/dev/null
fi
pass "federated credential (no client secret created)"

log "RBAC for the pipeline - resource group scope only"
az role assignment create --assignee-object-id "$GH_SP_OID" --assignee-principal-type ServicePrincipal \
  --role Contributor --scope "$RG_ID" \
  --description "CI deploys lab resources in this RG only" >/dev/null
pass "Contributor @ $RG"

# ABAC condition: the pipeline may create/delete role assignments ONLY for Key Vault Secrets User.
# It cannot hand out Owner, Contributor, or anything else - a stolen pipeline token cannot escalate.
COND="((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$KV_SECRETS_USER})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$KV_SECRETS_USER}))"
az role assignment create --assignee-object-id "$GH_SP_OID" --assignee-principal-type ServicePrincipal \
  --role "Role Based Access Control Administrator" --scope "$RG_ID" \
  --condition "$COND" --condition-version "2.0" \
  --description "CI may only assign Key Vault Secrets User (constrained delegation)" >/dev/null
pass "RBAC Administrator @ $RG, constrained to Key Vault Secrets User"

log "GitHub: protected environment + non-secret variables"
if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  gh api -X PUT "repos/$GITHUB_REPO/environments/lab" >/dev/null && pass "environment 'lab'"
  echo "  -> Add yourself as a Required reviewer: Settings > Environments > lab"
  gh variable set AZURE_CLIENT_ID       -R "$GITHUB_REPO" --body "$GH_APP_ID"
  gh variable set AZURE_TENANT_ID       -R "$GITHUB_REPO" --body "$TENANT_ID"
  gh variable set AZURE_SUBSCRIPTION_ID -R "$GITHUB_REPO" --body "$SUB_ID"
  gh variable set AZURE_RG              -R "$GITHUB_REPO" --body "$RG"
  gh variable set LAB_SUFFIX            -R "$GITHUB_REPO" --body "$(cat "$STATE/suffix")"
  [[ -f "$STATE/env.sh" ]] && { load_outputs; gh variable set KV_ALLOWED_IPS -R "$GITHUB_REPO" --body "[\"$MY_IP\"]"; }
  [[ -f "$STATE/vm_key.pub" ]] && gh variable set VM_SSH_PUBLIC_KEY -R "$GITHUB_REPO" --body "$(cat "$STATE/vm_key.pub")"
  pass "repository variables set (identifiers, not secrets)"
else
  warn "gh CLI not logged in. Set these as repository VARIABLES (not secrets) by hand:"
  echo "  AZURE_CLIENT_ID=$GH_APP_ID  AZURE_TENANT_ID=<tenant>  AZURE_SUBSCRIPTION_ID=<sub>  AZURE_RG=$RG"
fi

log "Prove there is no password on the app"
n="$(azq ad app credential list --id "$GH_APP_ID" --query "length(@)" -o tsv)"
[[ "$n" == "0" ]] && pass "0 client secrets / certificates" || fail "$n credential(s) found on the app"

summary
