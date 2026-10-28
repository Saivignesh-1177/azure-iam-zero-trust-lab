# Azure IAM Zero Trust Lab

[![ci](https://github.com/Saivignesh-1177/azure-iam-zero-trust-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Saivignesh-1177/azure-iam-zero-trust-lab/actions/workflows/ci.yml)

**Problem:** an attacker gets the application's source code, its config, or a shell on the box it
runs on. What can they steal?

**Answer this lab proves:** no reusable credential exists anywhere; the workload's identity can read
**exactly one secret** and nothing else; that secret is reachable **only from the workload's subnet**;
and every read, denial and permission change is **logged and alerted** — built only on free Azure
and GitHub resources, defined as code, tested before deployment, and verified after it.

| | |
|---|---|
| **Skills** | Azure RBAC & ABAC conditions · managed identities · Key Vault · network isolation · Bicep IaC · Azure Policy · Defender CSPM · KQL detection · GitHub OIDC (secretless CI/CD) · threat modeling · GRC traceability |
| **Frameworks** | NIST SP 800-53 Rev 5 (29 controls) · NIST CSF 2.0 · NIST SP 800-207 · OWASP Top 10 / CI/CD Top 10 / ASVS · CIS Azure · MITRE ATT&CK · MCSB |
| **Cost** | ≈ $0 (see [architecture.md](architecture.md#cost-summary)) |

## What's in here

| Path | What it is |
|---|---|
| [`architecture.md`](architecture.md) | Diagram, components, identity design, ADRs, cost |
| [`threat-model.md`](threat-model.md) | DFD + trust boundaries, STRIDE (T01–T15), ATT&CK, attack tree, residual risks |
| [`controls/control-mapping.csv`](controls/control-mapping.csv) | NIST 800-53 control → implementation → test → evidence → threat |
| [`controls/framework-crosswalk.md`](controls/framework-crosswalk.md) | Same controls mapped to CSF 2.0, 800-207, OWASP, CIS, ATT&CK, MCSB |
| [`infra/main.bicep`](infra/main.bicep) | Identity, Key Vault, secrets, scoped RBAC, logging, alerts, optional VM |
| [`infra/activity-log.bicep`](infra/activity-log.bicep) | Subscription Activity Log → Log Analytics |
| [`scripts/`](scripts) | `00` prereqs → `01` deploy → `02` verify → `03` policy → `04` evidence → `05` OIDC → `99` teardown |
| [`queries/`](queries) | KQL hunts: secret reads, denials, unexpected networks, RBAC changes, log tampering |
| [`tests/`](tests) | 31 tests on the compiled template, repo hygiene and GRC traceability |
| [`.github/workflows/`](.github/workflows) | CI (build, lint, tests, Checkov, Gitleaks) and OIDC deploy |
| [`COMMANDS.md`](COMMANDS.md) | **Every command**, raw, with the why — plus break-it drills |
| [`docs/lab-journal.md`](docs/lab-journal.md) | Handwritten-style build notes: decisions, gotchas, findings |
| [`docs/learning-path.md`](docs/learning-path.md) | How to go from "I ran it" to "I can design and defend it" |
| [`docs/incident-runbook.md`](docs/incident-runbook.md) | IR playbooks for token theft, escalation, log tampering, deletion |
| [`local-lab/`](local-lab) | **Hybrid:** on-prem Ubuntu server in VirtualBox, hardened by cloud-init, Azure Arc-enabled |
| [`app/`](app) | Stdlib-only Python service that reads its secret via the Arc identity; sandboxed systemd unit |
| [`attacks/`](attacks) | 8 adversary-emulation scenarios (insider, SSRF, root blast radius, token replay, brute force …) |
| [`evidence/`](evidence) | Redacted, hashed outputs from real runs only — first run: `evidence/2026-10-28/` |

## Quickstart (Azure Cloud Shell, ~20 minutes)

```bash
git clone https://github.com/Saivignesh-1177/azure-iam-zero-trust-lab.git && cd azure-iam-zero-trust-lab
chmod +x scripts/*.sh
BUDGET_EMAIL=you@example.com ./scripts/00-prereqs.sh                       # tools, providers, $5 budget alarm
DEPLOY_WORKLOAD=true ALERT_EMAIL=you@example.com ./scripts/01-deploy.sh   # deploy
./scripts/02-verify.sh                                                    # positive + negative tests
./scripts/03-policy.sh assign          # ...30 min later: ./scripts/03-policy.sh report
./scripts/04-evidence.sh                                                  # redacted, hashed evidence
./scripts/99-teardown.sh                                                  # when finished
```

Local checks without Azure: `az bicep build --file infra/main.bicep && pytest -v`

## Validation: how we know it works

| Layer | Check | Where |
|---|---|---|
| Before deploy | Bicep lint with security rules as errors | CI `bicep` job |
| Before deploy | 31 pytest tests on the **compiled ARM** (scope, firewall, purge protection, no public IP …) | CI `tests` job |
| Before deploy | Checkov IaC scan (20 pass, 4 risk-accepted skips with written justification) | CI `checkov` job → Security tab |
| Before deploy | Gitleaks over full git history | CI `secrets` job |
| After deploy | Control-plane checks C1–C5 (role count/scope, vault config, logging) | `scripts/02-verify.sh` |
| After deploy | **From inside the workload:** 1 allowed action, 7 denied | `scripts/vm/probe.sh` |
| Continuous | Azure Policy audit + Defender CSPM | `scripts/03-policy.sh` |
| Continuous | Activity-log alerts + KQL hunts | `infra/main.bicep`, `queries/` |

## Interview talking point

> "I designed workload access so there is nothing to steal: the app authenticates with a managed
> identity, and its only permission is Key Vault Secrets User on **one secret** — I deployed a decoy
> secret to prove the boundary with a 403. The vault is default-deny on the network, so even a stolen
> token is useless from outside the subnet. CI/CD uses GitHub OIDC with zero stored secrets, and the
> pipeline can only grant that one role because of an ABAC condition. I threat-modeled it with STRIDE,
> mapped 29 NIST 800-53 controls with traceability tests that fail the build if a threat loses its
> control, and kept only real, redacted, hashed evidence. The residual risks — no Private Endpoint,
> no PIM — are documented with the compensating controls and the paid upgrade path."

## Status

- [x] Design, threat model, control mapping
- [x] Static validation: build, lint, 31 tests, Checkov, mutation check
- [x] Scripts for deploy, verify, policy, evidence, OIDC, teardown
- [x] Azure execution — baseline deployed, 19/19 control-plane checks (2026-10-28)
- [x] Hybrid workload — VirtualBox server, Azure Arc identity, app live, secret hash verified
- [x] Attack scenarios A01–A08 run; 2 findings (F-005 fixed + re-tested, RISK-08 accepted)
- [x] Real evidence captured — `evidence/2026-10-28/` (26 files, SHA-256 verified)
- [ ] Azure Policy + Defender report (EVD-008/012)
- [ ] GitHub OIDC deploy run (EVD-010)
- [ ] MFA screenshot (EVD-011)
