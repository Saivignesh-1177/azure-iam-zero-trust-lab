# Framework Crosswalk

The authoritative control list is `control-mapping.csv` (NIST SP 800-53 Rev 5). This page maps the
same implementation to the other frameworks recruiters and auditors ask about, so you can answer
"how does this meet X?" for any of them from one lab.

> Naming note: CIS benchmark item *numbers* change between versions, so CIS items are referenced by
> title. Check the version your employer uses before quoting a number.

## 1. NIST Cybersecurity Framework 2.0

| CSF 2.0 | Outcome | Where in this lab |
|---|---|---|
| GV.RM | Risk management strategy | `threat-model.md` scoring + residual risk register |
| GV.SC | Supply-chain risk | Dependabot, OIDC-only pipeline, env approval |
| ID.AM | Asset inventory | Tags on every resource; assets table A1–A7 |
| ID.RA | Risk assessment | STRIDE + ATT&CK mapping |
| PR.AA-01/02 | Identities and credentials managed | Managed identity, no static credentials |
| PR.AA-05 | Least privilege, separation of duties | Secret-scoped Secrets User; admin ≠ workload ≠ pipeline |
| PR.DS-01 | Data-at-rest protected | Key Vault, platform disk encryption |
| PR.DS-02 | Data-in-transit protected | TLS to Key Vault and IMDS |
| PR.PS-01 | Configuration management | Bicep baseline, what-if, Azure Policy |
| PR.PS-04 | Log records generated | AuditEvent + Activity Log |
| PR.IR-01 | Networks protected from unauthorized access | Vault firewall, NSG, no public IP |
| DE.CM-01/03 | Networks and personnel activity monitored | KQL hunts, activity-log alerts |
| DE.AE-02 | Adverse events analyzed | `kv-denied-access.kql`, triage in runbook |
| RS.MA / RS.AN | Incident managed and analyzed | `docs/incident-runbook.md` |
| RC.RP | Recovery executed | Soft delete + purge protection, `az keyvault secret recover` |

## 2. NIST SP 800-207 Zero Trust tenets

| # | Tenet (paraphrased) | How the lab applies it |
|---|---|---|
| 1 | All data sources and services are resources | Each *secret* is its own RBAC scope, not just the vault |
| 2 | All communication is secured regardless of network location | TLS everywhere; being "inside" the VNet grants nothing without a token |
| 3 | Access is granted per-session | Short-lived MI/OIDC tokens; nothing long-lived to steal |
| 4 | Access is determined by dynamic policy | RBAC + network rules + ABAC condition on the pipeline |
| 5 | Monitor the integrity and security posture of all assets | Azure Policy, Defender CSPM, Checkov |
| 6 | Authentication and authorization are strictly enforced before access | IMDS token → Entra → Key Vault RBAC check on every call |
| 7 | Collect as much information as possible to improve posture | AuditEvent + Activity Log + hunts feed back into the threat model |

## 3. OWASP

### OWASP Top 10 (2021)

| Item | Relevance here | Control |
|---|---|---|
| A01 Broken Access Control | Workload reading secrets it doesn't need | Secret-scoped RBAC; decoy probe proves 403 |
| A02 Cryptographic Failures | Secrets in plaintext config | Key Vault, TLS, no secrets in code |
| A05 Security Misconfiguration | Open vault firewall, public VM | Default Deny, no public IP, Policy, Checkov |
| A07 Identification & Authentication Failures | Static shared credentials | Managed identity, OIDC, MFA |
| A08 Software & Data Integrity Failures | Unreviewed pipeline changes | Protected env, manual deploy, Dependabot |
| A09 Security Logging & Monitoring Failures | No record of secret access | AuditEvent, alerts, KQL hunts |
| A10 Server-Side Request Forgery | App fetches attacker-chosen URLs → local identity endpoint | Arc challenge-response; F-005 fix (scheme allow-list, internal-IP block, no redirects); attack A03 → re-test A08 |

### OWASP Top 10 CI/CD Security Risks

| Risk | Control |
|---|---|
| CICD-SEC-1 Insufficient Flow Control | Deploy requires `workflow_dispatch` + environment reviewer |
| CICD-SEC-2 Inadequate IAM | Pipeline identity scoped to one RG, ABAC-constrained RBAC admin |
| CICD-SEC-3 Dependency Chain Abuse | Dependabot on actions and pip |
| CICD-SEC-4 Poisoned Pipeline Execution | PR workflows: `contents: read`, no `id-token`, no Azure login |
| CICD-SEC-5 Insufficient PBAC | Per-job `permissions:` blocks |
| CICD-SEC-6 Insufficient Credential Hygiene | **Zero** stored cloud secrets; OIDC federation |
| CICD-SEC-7 Insecure System Configuration | Env vars instead of inline `${{ }}` in shell (injection) |
| CICD-SEC-10 Insufficient Logging | Workflow run logs + Azure Activity Log for every deploy |

### OWASP ASVS / Cheat Sheets

- **ASVS v4.0.3 V6.4 (Secret Management):** secrets kept in a vault, not in code or config — met.
- **ASVS v4.0.3 V1.6 / V14 (configuration):** no credentials in source, hardened build pipeline — met.
- **Secrets Management Cheat Sheet:** centralise, rotate (expiry + redeploy), audit, least privilege — met.
- **CI/CD Security Cheat Sheet:** OIDC instead of long-lived secrets, protected environments — met.

> OWASP **GenAI / LLM Top 10** lives in portfolio project 5 (`ai-security-guardrails`).

## 4. CIS Microsoft Azure Foundations Benchmark (by title)

| CIS recommendation (Key Vault / IAM / logging sections) | Status |
|---|---|
| Ensure the Key Vault is recoverable (soft delete + purge protection) | ✅ |
| Enable Role Based Access Control for Azure Key Vault | ✅ |
| Ensure that the expiration date is set for all secrets | ✅ |
| Ensure that logging for Azure Key Vault is enabled | ✅ |
| Ensure Private Endpoints are used for Azure Key Vault | ❌ RISK-01 (cost) |
| Ensure a Diagnostic Setting exists for the subscription Activity Log | ✅ |
| Ensure activity log alerts exist for role/security-relevant operations | ✅ (RBAC, vault, diagnostic settings) |
| Ensure security defaults / MFA are enabled | ✅ manual evidence EVD-011 |
| Ensure no custom subscription Owner roles are created | ✅ (no custom roles; audited by policy) |

## 5. MITRE ATT&CK (Cloud / IaaS / Entra ID)

| Technique | Threat | Mitigation / detection in the lab |
|---|---|---|
| T1552.001 Credentials in Files | T01 | No credentials exist; Gitleaks |
| T1528 Steal Application Access Token | T02 | Network-bound vault; `kv-access-from-unexpected-network.kql` |
| T1550.001 Application Access Token | T02 | Same |
| T1555.006 Cloud Secrets Management Stores | T03 | Secret-scoped RBAC; `kv-denied-access.kql` |
| T1098.003 Additional Cloud Roles | T04 | No write rights; alert; `rbac-changes.kql` |
| T1485 Data Destruction | T06 | Purge protection; alert on vault delete |
| T1562.008 Disable or Modify Cloud Logs | T07 | Alert on diagnostic-setting delete |
| T1110 / T1021.004 Brute force / SSH | T11 | No inbound path at all |
| T1567 / T1537 Exfiltration | T12 | NSG egress deny Internet |
| T1078.004 Valid Accounts: Cloud | T15 | MFA; low-privilege daily role |

## 6. Microsoft Cloud Security Benchmark (MCSB) — quick map

IM-1/IM-3 (managed identities) · PA-7 (least privilege) · DP-6/DP-7 (Key Vault for secrets/keys) ·
NS-2 (secure cloud services with network controls) · LT-1/LT-3 (logging) · PV-2 (Azure Policy) ·
DS-6 (secure DevOps pipeline).
