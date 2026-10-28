# Learning Path — from "I ran the lab" to "I can design and defend it"

Mastery test for each module: **can you explain it on a whiteboard, break it on purpose, detect the
break, and fix it — without notes?** Tick a box only when the answer is yes.

Suggested pace: 1 module per 2–3 days, ~4 weeks total.

---

## Module 1 — Identity fundamentals (Entra ID & workload identity)

**Learn**
- Users vs. groups vs. service principals vs. managed identities (system- vs. user-assigned)
- How a managed identity gets a token: IMDS `169.254.169.254` → Entra → JWT. Claims: `oid`, `aud`, `xms_mirid`, `exp`
- App registration vs. enterprise application (service principal)
- Workload identity federation (OIDC): issuer, subject, audience

**Do**
- [ ] Decode a managed-identity token at jwt.ms and explain every claim
- [ ] Explain why a stolen MI token still works for ~24h, and what the lab does about it (T02)
- [ ] Change the OIDC subject to `ref:refs/heads/main` and observe `AADSTS70021`; explain why

**Interview questions**
1. System-assigned vs. user-assigned managed identity — when would you pick each?
2. How does a VM prove who it is without a password?
3. Why is OIDC federation better than a client secret in GitHub? What can still go wrong?

---

## Module 2 — Authorization: RBAC, scopes, data plane vs. control plane, ABAC

**Learn**
- Scope hierarchy: management group → subscription → RG → resource → *sub-resource (secret)*
- `actions` vs. `dataActions`; why Contributor **cannot** read Key Vault secrets in RBAC mode
- Owner vs. User Access Administrator vs. RBAC Administrator
- ABAC conditions on role assignments (constrained delegation)
- Key Vault access policies (legacy) vs. Azure RBAC model

**Do**
- [ ] `az role definition list --name "Contributor" --query "[].permissions"` — find `notDataActions` / missing dataActions
- [ ] Drill 1 in COMMANDS.md (vault-wide grant) → see the decoy read succeed → revert
- [ ] Write your own ABAC condition that also restricts `PrincipalType` to `ServicePrincipal`

**Interview questions**
1. Contributor on a subscription — can they read Key Vault secrets? (RBAC mode vs. access-policy mode)
2. How do you let a pipeline create role assignments without letting it become Owner?
3. How long does an RBAC change take to apply, and why does it matter during an incident?

---

## Module 3 — Secrets management (Key Vault)

**Learn**
- Secrets vs. keys vs. certificates; Standard vs. Premium (HSM)
- Soft delete, purge protection, retention; what "recoverable" means
- Rotation patterns: expiry, versions, event-driven rotation (Event Grid `SecretNearExpiry`)
- Why secure parameters / `newGuid()` keep values out of humans' hands

**Do**
- [ ] Drill 4 (delete + try purge + recover)
- [ ] Rotate the secret by redeploying; show the new version and that the app still works
- [ ] Explain the difference between disabling a secret version and deleting the secret

---

## Module 4 — Network security for PaaS

**Learn**
- Public endpoint + firewall vs. service endpoint vs. private endpoint (+ private DNS)
- NSG evaluation order, default rules, service tags; effective rules
- "Default outbound access" retirement and explicit egress design
- Why network controls make stolen tokens less useful (defense in depth)

**Do**
- [ ] `az network nic list-effective-nsg` and explain every rule including the defaults
- [ ] Remove your IP from the vault firewall; read the exact error; restore
- [ ] *Stretch (paid, ~$0.25/day):* add a Private Endpoint + private DNS zone, set `publicNetworkAccess: Disabled`, close RISK-01, then delete it

---

## Module 5 — Infrastructure as Code security

**Learn**
- Bicep basics: params, `@secure()`, conditions, loops, `existing`, scopes, outputs
- What-if as change control; incremental vs. complete mode
- Linting (bicepconfig.json), Checkov, PSRule for Azure; SARIF; why scan the compiled ARM
- Policy as code: Audit vs. Deny vs. DeployIfNotExists vs. Modify

**Do**
- [ ] Add a new Checkov skip *without* a justification — then argue in the PR why that's bad
- [ ] Write one custom Azure Policy (JSON) that denies Key Vaults with `defaultAction: Allow`
- [ ] Run PSRule: `Install-Module PSRule.Rules.Azure; Assert-PSRule -Module PSRule.Rules.Azure -InputPath compiled/` and compare to Checkov

---

## Module 6 — Logging, detection & response

**Learn**
- Activity Log (control plane) vs. resource logs (data plane) vs. Entra sign-in logs
- Diagnostic settings, Log Analytics tables (`AzureDiagnostics`, `AzureActivity`), retention & cost
- KQL: `where`, `project`, `summarize`, `make_set`, `join`, `bin`, time windows
- Activity-log alerts (free) vs. log search alerts (paid) vs. Sentinel analytics rules
- NIST SP 800-61 incident phases

**Do**
- [ ] Write a KQL query: "identities with > 5 denied secret reads in 10 minutes" (`bin(TimeGenerated, 10m)`)
- [ ] Run the scenario 1 tabletop in `docs/incident-runbook.md` end to end with a timer
- [ ] Measure: action → log visible (minutes) and action → alert email (minutes). Write both in the journal

---

## Module 7 — GRC: NIST, CSF, OWASP, CIS — and evidence

**Learn**
- NIST SP 800-53 Rev 5 families you used: AC, AU, CA, CM, CP, IA, IR, RA, SA, SC, SI, SR
- Control enhancements (e.g. AC-6(1), AC-6(9), AC-6(10), IA-5(7)) and why auditors care
- NIST CSF 2.0 functions (GV, ID, PR, DE, RS, RC); SP 800-207 tenets; SP 800-61 IR
- OWASP Top 10 (A01, A05, A07, A09) and the **OWASP Top 10 CI/CD Security Risks**
- Shared responsibility & inherited controls (SC-8 here)
- What makes evidence credible: real, timestamped, redacted, hashed, failures kept

**Do**
- [ ] Pick 5 rows in `control-mapping.csv`; for each, show the auditor the test *and* the evidence in < 2 min
- [ ] Add one new threat (e.g. "VM image tampering") and see `test_traceability.py` fail until you map it
- [ ] Write a 1-page risk acceptance memo for RISK-01 (risk, likelihood, impact, compensating controls, owner, review date)

---

## Module 8 — Threat modeling

**Learn**
- STRIDE per element; DFDs and trust boundaries; attack trees
- Scoring (L×I, DREAD, CVSS-for-design); inherent vs. residual risk
- ATT&CK for Cloud as the "how would they actually do it" lens

**Do**
- [ ] Redraw the DFD from memory
- [ ] Threat-model a variation: the workload is a Container App instead of a VM. What changes?
- [ ] Free tool practice: model this lab in OWASP Threat Dragon or Microsoft Threat Modeling Tool

---

## Capstone — prove mastery

- [ ] Tear everything down and rebuild from an empty subscription **without the scripts**, using only
      your memory and `az --help`. Time it.
- [ ] Give a 10-minute talk: problem → design → threat model → controls → evidence → residual risk.
- [ ] Answer "what would you do with a $500/month budget?" (Private Endpoints, PIM, Conditional
      Access, Sentinel, Azure Firewall, Defender for Key Vault).

---

## Résumé bullets (use only after you've done the run and have evidence)

- Designed and deployed a zero-trust workload-identity pattern in Azure (managed identity, secret-scoped
  RBAC, default-deny Key Vault firewall), verified with 1 permitted and 7 denied in-workload probes.
- Built secretless CI/CD with GitHub OIDC federation and an ABAC-constrained RBAC delegation that
  prevents pipeline privilege escalation.
- Mapped 29 NIST SP 800-53 Rev 5 controls with automated traceability tests linking 15 STRIDE threats
  to controls and hashed, redacted evidence; crosswalked to NIST CSF 2.0, OWASP, CIS and MITRE ATT&CK.
- Shift-left IaC security: Bicep lint rules as errors, 31 tests on compiled ARM with mutation checks,
  Checkov (SARIF to GitHub code scanning) and Gitleaks in CI.

## Related certifications this lab prepares you for

AZ-500 (Azure Security Engineer) · SC-300 (Identity and Access Administrator) · SC-100
(Cybersecurity Architect) · and the identity/GRC domains of CCSP, CISSP and Security+.

## Free study resources

- Microsoft Learn: AZ-500 & SC-300 learning paths (free), Azure Key Vault and RBAC docs
- NIST CSRC: SP 800-53 Rev 5, SP 800-53A (assessment procedures), CSF 2.0, SP 800-207, SP 800-61
- OWASP: Top 10, Top 10 CI/CD Security Risks, ASVS, Cheat Sheet Series (Secrets Management, CI/CD)
- MITRE ATT&CK: Cloud matrix (IaaS, Identity Provider)
- CIS: Microsoft Azure Foundations Benchmark (free PDF with registration)
