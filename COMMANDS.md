# COMMANDS — every command used to build, check, and prove this lab

The `scripts/` folder automates everything below. This file shows the **raw commands** each script
runs, in order, with the *why* — so you can type them by hand, understand them, and explain them in
an interview. Commands are bash (Azure Cloud Shell or Git Bash). PowerShell differences are noted.

> 🟢 = free · 🟡 = pennies · 🔴 = costs money if left running

---

## 0. Get the free resources

| What | Where | Notes |
|---|---|---|
| Azure free account | https://azure.microsoft.com/free | $200 credit for 30 days + 12 months of free services (B1s VM, 2× P6 disks) + always-free services (Policy, Defender CSPM foundational, RBAC, managed identities). Keep the **spending limit ON**. |
| Azure for Students (alternative) | https://azure.microsoft.com/free/students | $100 credit, no credit card, renews yearly while you're a student |
| Azure Cloud Shell | https://shell.azure.com | Free Linux shell with `az`, `bicep`, `git`, `python3`, `jq`. Pick **ephemeral session** (no storage account needed). **Recommended place to run the scripts.** |
| GitHub | public repo | Actions minutes and code scanning are free for public repos |
| Entra ID P2 trial (optional) | Entra admin center → Licenses → Try/Buy | 30 days free: lets you practise PIM and Conditional Access (RISK-05) |

---

## 1. Tooling

```bash
# Cloud Shell: already installed. Just clone:
git clone https://github.com/Saivignesh-1177/azure-iam-zero-trust-lab.git && cd azure-iam-zero-trust-lab

# Windows (PowerShell) - one time
winget install -e --id Microsoft.AzureCLI
winget install -e --id Git.Git
winget install -e --id Python.Python.3.12
winget install -e --id GitHub.cli
az bicep install                       # Bicep compiler (az downloads it to ~/.azure/bin)
pip install -r requirements-dev.txt    # pytest
pip install checkov                    # IaC scanner (if pip fails with "path too long", use a venv in a short path like C:\cv)
winget install -e --id Gitleaks.Gitleaks   # secret scanner
```

---

## 2. Log in and set guard-rails  → `scripts/00-prereqs.sh`

```bash
az login                                       # browser + MFA (security defaults)
az account show -o table                       # confirm the right subscription
az account set --subscription "<name-or-id>"   # if you have more than one

# Register resource providers 🟢 (once per subscription)
for ns in Microsoft.KeyVault Microsoft.ManagedIdentity Microsoft.OperationalInsights Microsoft.Insights \
          Microsoft.Network Microsoft.Compute Microsoft.PolicyInsights Microsoft.Security; do
  az provider register -n $ns; done
az provider show -n Microsoft.KeyVault --query registrationState

# Let az auto-install extensions it needs (log-analytics query, etc.)
az config set extension.use_dynamic_install=yes_without_prompt

# Budget: email at 50% actual / 100% forecast of $5  🟢
BUDGET_EMAIL=you@example.com ./scripts/00-prereqs.sh
```

Check MFA is on (evidence EVD-011): Entra admin center → **Overview → Properties → Manage security
defaults** → screenshot showing *Enabled*.

---

## 3. Validate locally — before anything touches Azure 🟢

```bash
# Compile Bicep -> ARM. bicepconfig.json turns security lint rules into errors.
az bicep build --file infra/main.bicep --stdout > /dev/null && echo BUILD OK
az bicep lint  --file infra/main.bicep
az bicep build --file infra/activity-log.bicep --stdout > /dev/null

# Design + hygiene + GRC traceability tests (31 tests)
pytest -v

# IaC security scan on the compiled template (skips are justified in .checkov.yaml)
mkdir -p compiled && az bicep build --file infra/main.bicep --outfile compiled/main.json
checkov -d compiled --config-file .checkov.yaml

# Secret scan of the whole git history
gitleaks detect --source . --redact -v
```

**Mutation test** (proves the tests actually test something):
```bash
cp infra/main.bicep /tmp/main.bak
sed -i "s/  scope: appSecret$/  scope: vault/" infra/main.bicep   # widen access to the whole vault
pytest -q                                                       # must FAIL: test_workload_role_is_scoped_to_a_single_secret
cp /tmp/main.bak infra/main.bicep && pytest -q                  # back to green
```

---

## 4. Deploy  → `scripts/01-deploy.sh`

```bash
# Baseline only (identity + vault + logging) 🟢
./scripts/01-deploy.sh

# Full lab: + probe VM 🔴(free on a free account) + email alerts 🟢
DEPLOY_WORKLOAD=true ALERT_EMAIL=you@example.com ./scripts/01-deploy.sh
```

What it runs, by hand:
```bash
RG=rg-sc500-iam-zt-lab; LOCATION=eastus; SUFFIX=zt$(date +%m%d)$((RANDOM%1000))
ADMIN_OID=$(az ad signed-in-user show --query id -o tsv)   # your Entra object id
MY_IP=$(curl -s https://api.ipify.org)                    # for the vault firewall allow-list

az group create -n $RG -l $LOCATION --tags project=azure-iam-zero-trust-lab environment=lab

ssh-keygen -t ed25519 -N "" -f .state/vm_key -q           # only if deploying the VM (key is never used to log in)

# ALWAYS preview first - this is your change record
az deployment group what-if -g $RG -n zt-main -f infra/main.bicep \
  -p suffix=$SUFFIX adminPrincipalId=$ADMIN_OID allowedIpRanges="['$MY_IP']" \
     deployWorkload=true vmSshPublicKey="$(cat .state/vm_key.pub)" alertEmail=you@example.com

az deployment group create -g $RG -n zt-main -f infra/main.bicep -p <same params>

az deployment group show -g $RG -n zt-main --query properties.outputs   # ids only, never secrets

# Subscription Activity Log -> workspace (free ingestion)
WS_ID=$(az deployment group show -g $RG -n zt-main --query properties.outputs.workspaceId.value -o tsv)
az deployment sub create -l $LOCATION -n sc500-activity-log -f infra/activity-log.bicep -p workspaceId=$WS_ID
```

> ⏱ RBAC changes take up to ~5–10 minutes to propagate. If the next step says 403 for *you*, wait.

---

## 5. Verify identity & least privilege  → `scripts/02-verify.sh` (C1–C5)

```bash
source .state/env.sh   # OUT_* variables written by 01-deploy.sh

# C1/C2 - what can the workload identity do? Expect exactly ONE row: Secrets User on ONE secret
az role assignment list --assignee $OUT_identityPrincipalId --all \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table

# And the admin? Secrets Officer on the vault (plus Owner on a free subscription -> RISK-05)
az role assignment list --assignee $ADMIN_OID --all --query "[].{role:roleDefinitionName, scope:scope}" -o table

# C3 - vault hardening in one view
az keyvault show -n $OUT_keyVaultName --query "{rbac:properties.enableRbacAuthorization, \
  softDelete:properties.enableSoftDelete, purgeProtection:properties.enablePurgeProtection, \
  retentionDays:properties.softDeleteRetentionInDays, firewall:properties.networkAcls.defaultAction, \
  bypass:properties.networkAcls.bypass, ipRules:properties.networkAcls.ipRules[].value, \
  vnetRules:length(properties.networkAcls.virtualNetworkRules)}" -o jsonc

# C4 - secret metadata (never the value)
az keyvault secret list --vault-name $OUT_keyVaultName \
  --query "[].{name:name, expires:attributes.expires, type:contentType}" -o table

# C5 - logging
az monitor diagnostic-settings list --resource $OUT_keyVaultId -o table
az monitor diagnostic-settings subscription list -o table

# What could someone *with* a role do? Inspect the role's data actions
az role definition list --name "Key Vault Secrets User" --query "[].permissions[].dataActions" -o jsonc
az role definition list --name "Key Vault Secrets Officer" --query "[].permissions[].dataActions" -o jsonc

# Run the whole thing
./scripts/02-verify.sh
```

---

## 6. Prove it from the workload's point of view → `scripts/02-verify.sh` (C7–C8)

```bash
# No public IP, password login off
az vm list-ip-addresses -g $RG -n $OUT_vmName -o table
az vm show -g $RG -n $OUT_vmName --query osProfile.linuxConfiguration.disablePasswordAuthentication

# Run the probe INSIDE the VM - no SSH, no open port. Prints status codes + a hash, never the value.
az vm run-command invoke -g $RG -n $OUT_vmName --command-id RunShellScript \
  --scripts @scripts/vm/probe.sh \
  --parameters $OUT_identityClientId $OUT_keyVaultName $(az account show --query id -o tsv) \
               $OUT_appSecretName $OUT_decoySecretName \
  --query "value[0].message" -o tsv
```

What the probe does on the VM, line by line (try these yourself in a run-command):
```bash
# 1. Ask IMDS (link-local, only reachable from inside the VM) for a token - no secret involved
curl -s -H Metadata:true \
 "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net&client_id=<MI_CLIENT_ID>"
# 2. Use it
curl -s -H "Authorization: Bearer $TOKEN" "https://<vault>.vault.azure.net/secrets/app-db-password?api-version=7.4"        # 200
curl -s -H "Authorization: Bearer $TOKEN" "https://<vault>.vault.azure.net/secrets/unrelated-team-secret?api-version=7.4"  # 403 ForbiddenByRbac
```
Decode a token (paste into https://jwt.ms — lab tokens only) and find `oid`, `aud`, `xms_mirid`, `exp`.

---

## 7. Prove the network boundary (SC-7)

```bash
# From Cloud Shell (its IP is NOT in the allow-list) - expect ForbiddenByFirewall
az keyvault secret show --vault-name $OUT_keyVaultName -n $OUT_appSecretName

# From your laptop (allow-listed) - expect success for metadata
az keyvault secret show --vault-name $OUT_keyVaultName -n $OUT_appSecretName --query attributes

# Temporarily remove your IP and watch it fail, then add it back
az keyvault network-rule remove -n $OUT_keyVaultName --ip-address $MY_IP/32
az keyvault network-rule add    -n $OUT_keyVaultName --ip-address $MY_IP

# NSG rules actually applied to the VM NIC
az network nic list-effective-nsg -g $RG -n ${OUT_vmName}-nic -o table
```

---

## 8. Logging, detection & hunting (AU-2/6/12, SI-4)

```bash
WS=$OUT_workspaceCustomerId
# Every hunt in queries/ (logs take 5-15 min to arrive)
for q in queries/*.kql; do echo "== $q"; az monitor log-analytics query -w $WS --timespan P1D \
  --analytics-query "$(cat $q)" -o table; done

# Quick ad-hoc: last 20 vault operations
az monitor log-analytics query -w $WS -o table --analytics-query \
 'AzureDiagnostics | where ResourceProvider=="MICROSOFT.KEYVAULT" | take 20
  | project TimeGenerated, OperationName, httpStatusCode_d, CallerIPAddress, identity_claim_oid_g'

# Activity Log straight from Azure (no workspace needed, 90 days)
az monitor activity-log list -g $RG --offset 1d \
  --query "[].{time:eventTimestamp, op:operationName.value, caller:caller, status:status.value}" -o table

# Alerts that exist
az monitor activity-log alert list -g $RG -o table

# Fire the RBAC alert on purpose (then delete) - check your inbox
az role assignment create --assignee $ADMIN_OID --role Reader --scope /subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RG
az role assignment delete --assignee $ADMIN_OID --role Reader -g $RG
```

---

## 9. Compliance: Azure Policy + Defender for Cloud → `scripts/03-policy.sh` 🟢

```bash
./scripts/03-policy.sh assign          # assigns 10 built-in audit policies to the RG
# ~30 minutes later
./scripts/03-policy.sh report

# By hand
az policy definition list --query "[?contains(displayName,'Key Vault')].{name:name, displayName:displayName}" -o table
az policy assignment create --name zt-kv-rbac --policy <definition-name-guid> \
  --scope /subscriptions/<sub>/resourceGroups/$RG
az policy state trigger-scan -g $RG --no-wait
az policy state summarize -g $RG
az policy state list -g $RG --filter "complianceState eq 'NonCompliant'" \
  --query "[].{policy:policyDefinitionName, resource:resourceId}" -o table

# Defender for Cloud (foundational CSPM is free)
az security pricing list --query "value[].{plan:name, tier:pricingTier}" -o table   # leave plans on Free
az security secure-scores list -o table
az security assessment list --query "[?status.code=='Unhealthy'].{rec:displayName}" -o table
```

---

## 10. Secretless CI/CD with GitHub OIDC → `scripts/05-oidc-github.sh`

```bash
gh auth login                                      # once
GITHUB_REPO=Saivignesh-1177/azure-iam-zero-trust-lab ./scripts/05-oidc-github.sh
```
By hand:
```bash
APP_ID=$(az ad app create --display-name gh-oidc-azure-iam-zero-trust-lab --query appId -o tsv)
az ad sp create --id $APP_ID
SP_OID=$(az ad sp show --id $APP_ID --query id -o tsv)

# Trust ONLY this repo's "lab" environment
az ad app federated-credential create --id $APP_ID --parameters '{
  "name":"github-lab-environment","issuer":"https://token.actions.githubusercontent.com",
  "subject":"repo:Saivignesh-1177/azure-iam-zero-trust-lab:environment:lab",
  "audiences":["api://AzureADTokenExchange"]}'

az role assignment create --assignee-object-id $SP_OID --assignee-principal-type ServicePrincipal \
  --role Contributor --scope /subscriptions/<sub>/resourceGroups/$RG

# Constrained delegation (ABAC): may ONLY create/delete "Key Vault Secrets User" assignments
az role assignment create --assignee-object-id $SP_OID --assignee-principal-type ServicePrincipal \
  --role "Role Based Access Control Administrator" --scope /subscriptions/<sub>/resourceGroups/$RG \
  --condition-version 2.0 --condition "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {4633458b-17de-408a-b874-0445c86b69e6})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {4633458b-17de-408a-b874-0445c86b69e6}))"

az ad app credential list --id $APP_ID         # must be [] - there is no password to leak

# Repo variables (identifiers, not secrets) + protected environment
gh variable set AZURE_CLIENT_ID --body $APP_ID
gh variable set AZURE_TENANT_ID --body $(az account show --query tenantId -o tsv)
gh variable set AZURE_SUBSCRIPTION_ID --body $(az account show --query id -o tsv)
gh variable set AZURE_RG --body $RG
gh api -X PUT repos/Saivignesh-1177/azure-iam-zero-trust-lab/environments/lab
# Then: GitHub > Settings > Environments > lab > Required reviewers = you

gh workflow run deploy-lab -f deploy_workload=false   # run a deploy (approve it in the Actions tab)
gh run list --workflow deploy-lab
```

Prove the constraint works (should be **denied**): in a workflow step, or with the SP's token,
try `az role assignment create --role Owner ...` → `AuthorizationFailed ... condition`.

---

## 11. Package evidence → `scripts/04-evidence.sh`

```bash
./scripts/04-evidence.sh               # -> evidence/YYYY-MM-DD/ (redacted, leak-checked, hashed)
cat evidence/*/SHA256SUMS.txt
( cd evidence/2026-10-28 && sha256sum -c SHA256SUMS.txt )   # anyone can re-verify
git add evidence/ && git commit -m "evidence: lab run $(date +%F)"
```
Then fill in the Date / Result columns in `evidence/README.md`.

---

## 11b. Hybrid: on-prem server (VirtualBox) + Azure Arc → `local-lab/`, `app/`, `attacks/`

```powershell
# Verify the image (supply chain - SR-4): checksum AND signature
curl.exe -LO https://cloud-images.ubuntu.com/releases/noble/release/SHA256SUMS
curl.exe -LO https://cloud-images.ubuntu.com/releases/noble/release/SHA256SUMS.gpg
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81
gpg --verify SHA256SUMS.gpg SHA256SUMS            # "Good signature from UEC Image Automatic Signing Key"
# Build the VM (1 vCPU on purpose: SMP Linux can hang when VirtualBox runs on Hyper-V/NEM)
powershell -ExecutionPolicy Bypass -File local-lab\create-vm.ps1 -Python <python-with-pycdlib>
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list runningvms
```
```bash
K=.state/vbox/zt_lab_ed25519; O="-o UserKnownHostsFile=.state/vbox/known_hosts"
ssh -i $K $O ztadmin@192.168.56.10 'sudo ufw status verbose; sudo sshd -T | grep -E "password|root"'
# Arc onboard (device code + MFA, then monitor mode)
scp -i $K $O local-lab/arc-onboard.sh ztadmin@192.168.56.10:/tmp/
ssh -i $K $O ztadmin@192.168.56.10 "sudo bash /tmp/arc-onboard.sh rg-sc500-iam-zt-lab <sub> <tenant> eastus"
ssh -i $K $O ztadmin@192.168.56.10 'sudo azcmagent show; sudo azcmagent config list'
# Grant the Arc identity ONE secret, then install the app
export ARC_PRINCIPAL_ID=$(az resource show -g rg-sc500-iam-zt-lab -n zt-app-01   --resource-type Microsoft.HybridCompute/machines --query identity.principalId -o tsv)
ALERT_EMAIL=you@example.com ./scripts/01-deploy.sh
scp -i $K $O app/zt_app.py app/zt-app.service app/install-on-vm.sh ztadmin@192.168.56.10:/tmp/
ssh -i $K $O ztadmin@192.168.56.10 "sudo bash /tmp/install-on-vm.sh <vault-name>"
curl http://192.168.56.10:8080/secret-check
# Prove it's the right secret without ever printing it
az keyvault secret show --vault-name <vault> -n app-db-password --query value -o tsv | sha256sum | cut -c1-12
# Attack it (A06 bans your laptop for 2 minutes - by design)
./attacks/run-attacks.sh            # or: ./attacks/run-attacks.sh a03 a08
# On the server: what did the defenders see?
ssh -i $K $O ztadmin@192.168.56.10 'sudo ausearch --input-logs -k access_denied -ua intern -i | tail;   sudo fail2ban-client status sshd; sudo journalctl -u zt-app --since -1h | grep -E "ssrf|guarded"'
```
Gotchas: `ausearch` over SSH needs `--input-logs` (otherwise it reads stdin). Never debug with `bash -x`
(it prints tokens). Pause the server with `VBoxManage controlvm zt-app-01 acpipowerbutton`.

---

## 12. Break-it drills (do these to *master* it — each maps to a threat)

| # | Do this | Expected | Then |
|---|---|---|---|
| 1 | `az role assignment create --assignee $OUT_identityPrincipalId --role "Key Vault Secrets User" --scope $OUT_keyVaultId` (vault-wide) | Re-run probes: decoy now **200**. C1 fails. Alert email fires. | Delete it, re-verify. Write the finding in the journal. (T03) |
| 2 | `az keyvault update -n $OUT_keyVaultName --default-action Allow` | Cloud Shell can now read. Policy goes non-compliant. Vault-write alert fires. | `./scripts/01-deploy.sh` restores the baseline (drift fix). (T05, T14) |
| 3 | Delete the vault diagnostic setting | Alert fires; hunt shows the gap | Redeploy. (T07) |
| 4 | `az keyvault delete -n $OUT_keyVaultName` | Vault soft-deleted, `az keyvault purge` **refused** | `az keyvault recover -n $OUT_keyVaultName` (T06) |
| 5 | On a branch, add a line `db_password = "..."` with a 12-character fake value and commit | `pytest` and Gitleaks fail | Remove, and rewrite history if pushed (T01) |
| 6 | Add `pull_request:` to `deploy.yml` | `test_deploy_uses_oidc…` fails | Revert. Explain CICD-SEC-4 out loud. (T10) |

---

## 13. Tear down → `scripts/99-teardown.sh`

```bash
./scripts/99-teardown.sh
# By hand:
az policy assignment list -g $RG --query "[?starts_with(name,'zt-')].name" -o tsv | xargs -I{} az policy assignment delete -n {} -g $RG
az monitor diagnostic-settings subscription delete --name sc500-activity-to-law --yes
az ad app delete --id $APP_ID
az group delete -n $RG --yes
az keyvault list-deleted -o table      # stays soft-deleted for 7 days (purge protection); costs nothing

# Just pausing? Stop paying for compute but keep everything:
az vm deallocate -g $RG -n $OUT_vmName
az vm start      -g $RG -n $OUT_vmName
```

---

## 14. One-page cheat sheet

| Goal | Command |
|---|---|
| Who am I? | `az ad signed-in-user show --query "{name:displayName, id:id}"` |
| What can principal X do? | `az role assignment list --assignee <id> --all -o table` |
| What does role Y allow? | `az role definition list --name "<role>" --query "[].permissions"` |
| Who has access to resource Z? | `az role assignment list --scope <resource-id> --include-inherited -o table` |
| Vault posture | `az keyvault show -n <v> --query properties.networkAcls` |
| Preview a change | `az deployment group what-if -g <rg> -f infra/main.bicep -p …` |
| Recent control-plane activity | `az monitor activity-log list -g <rg> --offset 1d -o table` |
| Query logs | `az monitor log-analytics query -w <customerId> --analytics-query "<kql>"` |
| Compliance | `az policy state summarize -g <rg>` |
| Recover deleted secret | `az keyvault secret recover --vault-name <v> -n <name>` |
