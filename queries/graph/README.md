# Microsoft Graph queries — identity evidence (reusable)

KQL (`../*.kql`) answers *"what happened?"* from logs. These Graph queries answer
*"how is identity configured right now?"*: the questions an auditor asks about MFA, admins and
app credentials. All of them are **read-only** `GET`s.

## Three ways to run any query below

| Tool | How | When |
|---|---|---|
| **Graph Explorer** (web, free) | https://developer.microsoft.com/graph/graph-explorer → Sign in → paste URL → **Run query**. If you get 403, open **Modify permissions** → **Consent** to the listed permission | Quick, visual, nothing to install |
| **Microsoft Graph PowerShell** | `Install-Module Microsoft.Graph -Scope CurrentUser` then `Connect-MgGraph -Scopes "Policy.Read.All"` and `Invoke-MgGraphRequest -Method GET -Uri "<url>"` | Scripting / repeatable evidence |
| **Azure CLI** | `az rest --method get --url "<url>"` (escape `$` as `\$` in bash) | Only for permissions its token already has. Tested 2026-10-28: **Q5, Q6, Q8 work**; **Q1, Q2-details, Q3 return 403** → use Graph Explorer / PowerShell |

> Save outputs as evidence **only after redaction** (tenant ID, object IDs, UPNs, IPs).
> `scripts/redact_guids.py <file>` masks GUIDs; remove emails/UPNs by hand or with `lib.sh redact`.

---

## Q1 — Is MFA enforced by security defaults? (EVD-011) — free tier

```http
GET https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy
```
- **Permission:** `Policy.Read.All`
- **Good:** `"isEnabled": true`
- **Controls:** NIST IA-2(1)/IA-2(2) MFA · CSF PR.AA-03 · CIS "Ensure Security Defaults is enabled"
- PowerShell one-liner:
  ```powershell
  Connect-MgGraph -Scopes "Policy.Read.All"
  Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" | Select-Object displayName, isEnabled
  ```

## Q2 — Which Conditional Access policies exist? (needs Entra ID P1 to *create* them)

```http
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=displayName,state,conditions,grantControls
```
- **Permission:** `Policy.Read.All`
- **This tenant (2026-10-28):** 0 policies → MFA comes from security defaults (Q1).
  Security defaults and Conditional Access are mutually exclusive.

## Q3 — Which MFA methods are registered for me?

```http
GET https://graph.microsoft.com/v1.0/me/authentication/methods
```
- **Permission:** `UserAuthenticationMethod.Read`
- **Good:** at least one strong method besides password, e.g.
  `#microsoft.graph.microsoftAuthenticatorAuthenticationMethod` or `...fido2AuthenticationMethod`
- **Controls:** IA-2, IA-5

## Q4 — Who holds privileged directory roles? (least privilege for humans)

```http
GET https://graph.microsoft.com/v1.0/directoryRoles?$expand=members($select=displayName,userPrincipalName)&$select=displayName
```
- **Permission:** `RoleManagement.Read.Directory`
- **Good:** Global Administrator has 1–2 members (break-glass + you), nobody else.
- **Controls:** AC-2, AC-6(5) · RISK-05

## Q5 — Does the pipeline app have ANY password or certificate? (EVD-010c)

```http
GET https://graph.microsoft.com/v1.0/applications?$filter=displayName eq 'gh-oidc-azure-iam-zero-trust-lab'&$select=displayName,passwordCredentials,keyCredentials
```
- **Permission:** `Application.Read.All`
- **Good:** `"passwordCredentials": []` and `"keyCredentials": []` → secretless (OIDC only)
- **Result 2026-10-28:** 0 passwords, 0 certificates ✅
- **Controls:** IA-5(7) · OWASP CICD-SEC-6

## Q6 — What exactly does the pipeline app trust? (federated credentials)

```http
GET https://graph.microsoft.com/v1.0/applications(appId='<app-client-id>')/federatedIdentityCredentials
```
- **Permission:** `Application.Read.All`
- **Good:** one credential, `issuer = https://token.actions.githubusercontent.com`,
  `subject = repo:<owner>@<owner-id>/<repo>@<repo-id>:environment:lab` (immutable IDs — see F-011)

## Q7 — Recent sign-ins: did they actually use MFA? (API needs Entra ID P1)

```http
GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=10&$select=createdDateTime,appDisplayName,authenticationRequirement,conditionalAccessStatus,status
```
- **Permission:** `AuditLog.Read.All` — **the API requires P1**. On the free tier use the portal instead:
  Entra admin center → **Identity → Monitoring & health → Sign-in logs** → a sign-in →
  **Authentication Details** (kept 7 days on free tier).
- **Good:** `authenticationRequirement: multiFactorAuthentication`

## Q8 — Is the workload identity really a managed identity (no secrets)?

```http
GET https://graph.microsoft.com/v1.0/servicePrincipals?$filter=displayName eq 'zt-app-01'&$select=displayName,servicePrincipalType,passwordCredentials,keyCredentials
```
- **Permission:** `Application.Read.All`
- **Good:** `"servicePrincipalType": "ManagedIdentity"`, no password credentials
  (the Arc server's identity; repeat with `sc500-mi-<suffix>` for the cloud MI)
- **Result 2026-10-28:** `zt-app-01` → ManagedIdentity, 0 passwords; `sc500-mi-…` → ManagedIdentity ✅
- **Controls:** IA-9, IA-5(7)

---

### Gotchas hit on 2026-10-28 (real, not hypothetical)

| Symptom | Cause | Fix |
|---|---|---|
| `GET /me` returns a short `"id"` (16 hex chars, no dashes) | You're in the **personal Microsoft account** (consumer) context, not your Entra tenant. Tenant policies don't exist there | Use a tenant (work) account, or the Azure portal / CLI. `?tenant=<domain>` on Graph Explorer did **not** help for a Gmail-based tenant owner |
| `Connect-MgGraph : An error occurred when writing to a listener` | Known Microsoft.Graph module bug on **Windows PowerShell 5.1** | Use **PowerShell 7** (`winget install Microsoft.PowerShell`) |
| `az rest` → `403 required scopes are missing in the token` | The Azure CLI app's Graph token has no `Policy.Read.All` | Use Graph Explorer / Graph PowerShell for Q1–Q3 |
| A failed query wrote `"isEnabled": null` to a file | Script kept running after auth failed | Never keep null results as evidence: discard and record why |

Fallback for Q1 that always works: Azure portal → **Microsoft Entra ID → Properties → Manage security defaults**.

### Behavioural evidence beats configuration evidence

Configuration (Q1) says MFA *should* happen. The strongest proof is that it *did*: the first
`az login` on 2026-10-28 failed with `AADSTS50076 ... you must use multi-factor authentication`, and every
device-code login after that required MFA. Record both.
