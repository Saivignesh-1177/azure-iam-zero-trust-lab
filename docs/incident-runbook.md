# Incident Runbook — Workload Identity & Key Vault

NIST SP 800-61 phases: **Detect → Analyze → Contain → Eradicate → Recover → Lessons learned.**
Every command below works on the lab as deployed. Practise each scenario once as a tabletop.

Set these first (from `.state/env.sh` after a deploy):

```bash
source .state/env.sh
VAULT=$OUT_keyVaultName; WS=$OUT_workspaceCustomerId; MI=$OUT_identityPrincipalId; RG=rg-sc500-iam-zt-lab
```

---

## Scenario 1 — `app-db-password` read from an unexpected IP (suspected token theft, T02)

**Detect:** `queries/kv-access-from-unexpected-network.kql` returns rows.

**Analyze**
```bash
az monitor log-analytics query -w "$WS" --timespan P1D -o table --analytics-query '
AzureDiagnostics | where ResourceProvider=="MICROSOFT.KEYVAULT" and OperationName=="SecretGet"
| project TimeGenerated, CallerIPAddress, identity_claim_oid_g, httpStatusCode_d, id_s'
```
Questions: Is the object ID the workload's (`$MI`)? Is the IP the admin's? Did reads happen *after*
the VM was stopped?

**Contain** (in this order — fastest first)
```bash
# 1. Cut the identity off from the secret (takes effect in minutes)
az role assignment delete --assignee "$MI" --role "Key Vault Secrets User" \
  --scope "$OUT_keyVaultId/secrets/$OUT_appSecretName"
# 2. Make sure the vault firewall has nothing unexpected
az keyvault network-rule list -n "$VAULT"
# 3. Disable the current secret version so any copied value is useless downstream
az keyvault secret set-attributes --vault-name "$VAULT" -n "$OUT_appSecretName" --enabled false
```

**Eradicate:** rotate the secret (and the real credential it represents), rebuild the VM from the
image, review what code ran on it (`az vm run-command list`, Activity Log).

**Recover:** redeploy with `scripts/01-deploy.sh` (new secret value, role re-granted), run
`scripts/02-verify.sh`, watch the hunt query for 24h.

---

## Scenario 2 — Unexpected role assignment created (privilege escalation, T04)

**Detect:** activity-log alert email, or `queries/rbac-changes.kql`.

**Analyze**
```bash
az role assignment list -g "$RG" --include-inherited \
  --query "[].{who:principalName, type:principalType, role:roleDefinitionName, scope:scope, created:createdOn, by:createdBy}" -o table
```
Look at `createdBy` and compare against the change you expected (pipeline run, your own deploy).

**Contain**
```bash
az role assignment delete --ids <assignment-id>
# If the pipeline identity did it: kill its federation immediately
az ad app federated-credential delete --id "$GH_APP_ID" --federated-credential-id github-lab-environment
```

**Eradicate / Recover:** find out how the principal got the right to do this, remove that path,
re-run `scripts/02-verify.sh` (C1/C2 must pass again).

---

## Scenario 3 — Diagnostic settings deleted (defense evasion, T07)

**Detect:** alert on `Microsoft.Insights/diagnosticSettings/delete`, or a gap in AuditEvent data.

**Contain / Recover:** the IaC is the source of truth — just redeploy:
```bash
./scripts/01-deploy.sh
az monitor diagnostic-settings list --resource "$OUT_keyVaultId" -o table
```
**Analyze:** treat the window with no logs as "assume breach": check the Activity Log (it is kept
by Azure for 90 days independent of your export) for everything that caller did.
```bash
az monitor activity-log list -g "$RG" --offset 7d \
  --query "[?caller=='<caller>'].{time:eventTimestamp, op:operationName.value, status:status.value}" -o table
```

---

## Scenario 4 — Vault or secret deleted (destruction, T06)

```bash
az keyvault list-deleted -o table                      # vault soft-deleted?
az keyvault recover -n "$VAULT"                        # bring the vault back
az keyvault secret list-deleted --vault-name "$VAULT" -o table
az keyvault secret recover --vault-name "$VAULT" -n "$OUT_appSecretName"
```
Purge protection means nobody — including an attacker with Owner — can make this permanent
within the retention window. That is the whole point.

---

## Lessons-learned template

| Field | Notes |
|---|---|
| What happened (timeline, UTC) | |
| How was it detected? How long did that take? | |
| Which control held? Which one didn't? | |
| Threat-model rows to update | |
| New detection / test added | |
