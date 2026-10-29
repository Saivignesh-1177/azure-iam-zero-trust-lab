# Evidence

Evidence lives in dated folders (`evidence/YYYY-MM-DD/`) created by `scripts/04-evidence.sh`.
Each folder has a `SHA256SUMS.txt` so a reviewer can confirm nothing was edited after capture.

First real run: **`evidence/2026-10-28/`** (26 files, hashes in `SHA256SUMS.txt`). Rows still marked
`NOT RUN` have genuinely not been executed yet — see `../EVIDENCE_POLICY.md`.

## Rules

- Only store output produced by an actual test or deployment.
- Everything is redacted by `04-evidence.sh` (subscription, tenant, object IDs, IP, email) and then
  leak-checked. Raw, unredacted copies stay in `.state/` (gitignored).
- A FAIL stays a FAIL. Record it as a finding, fix it, re-run, and keep both runs.
- Never commit passwords, tokens, client secrets, private keys, or personal data.

## Evidence index

| ID | Artifact (in `evidence/<date>/`) | Proves | Produced by | Date | Result |
|---|---|---|---|---|---|
| EVD-001 | `EVD-001-bicep-build.txt` | Template compiles, linter security rules pass (CM-2) | `04-evidence.sh` | 2026-10-28 | PASS — build + lint clean |
| EVD-002 | `EVD-002-pytest.txt` | Design, hygiene and traceability tests pass (SA-11, RA-3) | `04-evidence.sh` | 2026-10-28 | PASS — 43/43 tests |
| EVD-003 | `EVD-003-iac-and-secret-scan.txt` | Checkov + Gitleaks clean (RA-5, IA-5(7)) | `04-evidence.sh` / CI | 2026-10-28 | PASS — Checkov 20/0 (Gitleaks runs in CI) |
| EVD-004 | `EVD-004-workload-role-assignments.json` | Workload has 1 role, on 1 secret (AC-6) | `02-verify.sh` C1–C2 | 2026-10-28 | PASS — 1 role, 1 secret scope |
| EVD-005 | `EVD-005-keyvault-config.json` | RBAC mode, purge protection, firewall Deny (AC-3, SC-7, CP-10) | `02-verify.sh` C3 | 2026-10-28 | PASS — RBAC, purge protection, Deny |
| EVD-006 | `EVD-006-keyvault-diagnostic-settings.json` | AuditEvent + Activity Log exported (AU-2, AU-12) | `02-verify.sh` C5 | 2026-10-28 | PASS — AuditEvent + Activity Log |
| EVD-007 | `EVD-007b-workload-probes.txt` | 1 allowed read, 7 denied actions from inside the workload (AC-3, AC-6(10), IA-9) | `02-verify.sh` C8 | 2026-10-28 | PARTIAL — C1–C5 PASS (19/19); C7/C8 N/A (no Azure VM, see EVD-013b) |
| EVD-008 | `EVD-008-policy-states.txt` | Azure Policy compliance incl. accepted RISK-01 (CM-6, CA-7) | `03-policy.sh report` | 2026-10-28 | PASS w/ 2 expected findings: 7 KV policies compliant; private link (RISK-01) + update check (RISK-09) non-compliant |
| EVD-009 | `EVD-009-kql-*.json` | Logs show who read/was denied what, RBAC changes (AU-6, SI-4) | `04-evidence.sh` | 2026-10-28 | PASS — reads, 10 denials, new-IP hunt populated |
| EVD-010 | `EVD-010-federated-credential.json` | Pipeline uses OIDC, 0 client secrets, ABAC-constrained (IA-5, AC-6(1)) | `05-oidc-github.sh` | 2026-10-28 | PASS: 0 client secrets, immutable-ID subject, ABAC condition; pipeline deploy succeeded after human approval, deployer = pipeline SP, public log leak-free (1st attempt failed closed: F-011) |
| EVD-011 | `EVD-011-security-defaults.png` | MFA enforced for the admin (IA-2) | Manual screenshot | 2026-10-28 | PASS (behavioural): MFA enforced on every sign-in — first `az login` blocked with AADSTS50076, 4 device-code logins required MFA; 0 Conditional Access policies → security defaults. Config screenshot optional |
| EVD-012 | `EVD-012-defender-recommendations.txt` | Defender CSPM posture for the RG (RA-5) | `03-policy.sh report` | 2026-10-28 | 6 MCSB findings, all explained: RISK-01, RISK-09/F-010 (no Guest Config data), SQL N/A |
| EVD-013 | `EVD-013-attack-run.txt` | Hybrid attack scenarios A01–A07 against the on-prem Arc server (AC-6, AC-7, SI-10, CM-7) | `attacks/run-attacks.sh` | 2026-10-28 | PASS with 2 findings (F-005 fixed + re-tested, RISK-08 accepted) |

## Expected results (so you know what "good" looks like)

| Probe (EVD-007) | Expected | Why |
|---|---|---|
| `imds_token` | `http=200` | The VM gets a token without any stored credential |
| `read_app_secret` | `http=200 len=36 sha256_12=…` | The one permitted action |
| `read_decoy_secret` | `http=403 error=Forbidden inner=ForbiddenByRbac` | Scoped to one secret |
| `list_secrets` | `http=403` | Cannot enumerate the vault |
| `write_secret` / `delete_secret` | `http=403` | Cannot tamper or destroy |
| `arm_list_rgs` | `http=403 error=AuthorizationFailed` | No control-plane rights |
| `graph_list_users` | `http=403` | No directory rights |
| `internet_egress` | `http=000` | NSG blocks internet egress |

If a result differs, that is a **finding**: write it up in `docs/lab-journal.md` (what, why, fix).
