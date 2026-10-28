# Lab Journal ✍️

*My working notes, written as I built this. Kept honest: anything I haven't run yet says so.
Things I'd tell myself if I started over are marked **→ note to self**.*

---

## 📅 2026-10-28 — Day 1: from starter template to something I can defend

### Where I started

The starter had one Bicep file: an identity, a vault, and a `Key Vault Secrets User` role on the
**whole vault**. The test was a string search for "owner" and "contributor". Status said
"design ✔, Azure ✘".

Honestly? It *looked* least-privilege, but it wasn't really:

- the role was vault-wide → the app could read **every** secret, now and in the future
- `publicNetworkAccess: Enabled` with **no firewall** → anyone with a token, from anywhere
- no logs → I couldn't prove who read what
- the test would pass even if I granted Owner by GUID (it searched for the *word* 'owner')

**→ note to self:** "least privilege" isn't a role name. It's role **+ scope + network + time**.

### Decision 1 — scope the role to ONE secret

Didn't know you could do this until I looked: Azure RBAC accepts a single secret
(`.../vaults/<v>/secrets/<name>`) as the scope. Zero cost. Massive blast-radius reduction.

But how do I *prove* it? A role you can't test is a role you're guessing about. So I added a
**decoy secret** (`unrelated-team-secret`). If the workload ever gets a 200 on the decoy, the design
is broken. That one idea turned the whole lab from "configured" into "verified". 💡

### Decision 2 — who generates the secret value?

If I `az keyvault secret set --value ...`, the value is in my shell history. Ugh.
Instead: `@secure() param appSecretValue string = newGuid()`. ARM generates it, ARM doesn't log
secure params, nobody ever sees it. Redeploy = rotation for free.

### Decision 3 — network without paying for Private Link

Private Endpoint ≈ $7/month. Not "free". So:

- vault firewall **default Deny**, `bypass: None` (don't even trust "trusted Microsoft services")
- allow my laptop IP (scripts detect it) + the workload subnet via a **service endpoint** (free)

Wrote it down as RISK-01 instead of pretending it's a Private Endpoint. Policy *will* flag it as
non-compliant — and that's fine; that's an honest finding with a compensating control.

### Decision 4 — how does the "app" run, for free?

Options I thought about:
- Function App → good, but newer plans are fiddly in Bicep and I can't easily run ad-hoc probes
- Container Apps → nice, but more moving parts
- **B1s VM** → free 750h/month on a free account, and `az vm run-command` lets me run code
  inside it **without SSH or any open port** ✅

So: no public IP, NSG deny-all inbound, password login off, egress only to Key Vault + Storage.
`run-command` needs a VM extension, so Checkov complains (CKV_AZURE_50) → RISK-03, justified.

⚠️ **Gotcha I designed around:** Azure is retiring "default outbound access" for new subnets. If the
default flips under me, the VM loses its path to Key Vault and the probe just times out. I set
`defaultOutboundAccess: true` explicitly and *then* lock egress down with the NSG, so the behaviour
doesn't depend on the date I deploy.

### Decision 5 — make tests check what Azure actually receives

Rewrote the tests to compile Bicep → ARM JSON and assert on the JSON.

First run: **3 failed** 😬. Not because the design was wrong — the compiler moves role GUIDs into
`variables('kvSecretsUserRoleId')`, so the raw GUID never appears in the role assignment. Wrote a tiny
resolver that inlines literal variables. → 24 passed.

Then I did a **mutation check** (break it on purpose, tests *must* fail):

| Mutation | Result |
|---|---|
| `scope: appSecret` → `scope: vault` | ❌ `test_workload_role_is_scoped_to_a_single_secret` |
| firewall `Deny` → `Allow` | ❌ `test_key_vault_firewall_default_deny` |
| (restored) | ✅ all green |

**→ note to self:** a test you've never seen fail is not a test yet.

### Decision 6 — Checkov said 6 failures. Two were *my* fault.

Ran Checkov against the compiled ARM (its Bicep parser choked on my file, ARM mode works fine).

| Check | What | Verdict |
|---|---|---|
| CKV_AZURE_110 purge protection | I'd written `enablePurgeProtection ? true : null` | **Real issue.** The scanner can't prove it's on. Hard-coded `true`. Fixed ✅ |
| CKV_AZURE_42 recoverable | same root cause | Fixed ✅ |
| CKV_AZURE_189 public network access | needed for IP/VNet rules | Accepted → RISK-01 |
| CKV_AZURE_50 VM extensions | run-command *is* an extension | Accepted → RISK-03 |
| CKV_AZURE_97 / 151 encryption at host | feature flag + SKU support | Accepted → RISK-04 (disks already SSE-encrypted) |

After: **20 passed, 0 failed**, 4 skips each with a comment in `.checkov.yaml` pointing at the risk ID.

**→ note to self:** making something configurable can make it *unverifiable*. Security settings
that should never be off shouldn't be parameters.

### Decision 7 — the pipeline must not have a password

GitHub → Azure with **OIDC federation**. The Entra app has *zero* client secrets; Azure trusts a
GitHub-signed token only if its subject is `repo:<me>/<repo>:environment:lab`.

Then the scary bit: Bicep creates a role assignment, so the pipeline needs
`roleAssignments/write`… which is basically "make yourself Owner". Fix: **Role Based Access Control
Administrator** with an **ABAC condition** — it may only create/delete assignments whose role is
`Key Vault Secrets User`. A stolen pipeline token can't escalate. 🔒

CI (runs on PRs) gets `contents: read` and **no** `id-token` → a malicious PR can't even ask for an
Azure token. Deploy is `workflow_dispatch` + environment approval only. Tests enforce both.

### Other small things today

- `bicep lint` flagged `secretExpiry` as "may be a secret" because of the word *secret* in the
  name 😄. Renamed to `expiryDate` instead of disabling the rule.
- My own secret-scan test missed `db_password = "..."` because `\b` doesn't match after an
  underscore. Fixed the regex, re-ran the drill → caught.
- Known Windows trap I designed around (haven't been bitten yet): Git Bash rewrites arguments like
  `/subscriptions/...` into `C:/Program Files/Git/subscriptions/...`. `export MSYS_NO_PATHCONV=1`
  in `scripts/lib.sh`. Also `az` on Windows prints CRLF → every captured value goes through `tr -d '\r'`.
  **→ note to self:** just use Cloud Shell.
- Checkov wouldn't even install on Windows in a deep folder ("filename too long" in a DLL path).
  Short-path venv fixed it. CI runs it on Linux anyway.

### Status at end of day 1

- ✅ build + lint clean · ✅ 31/31 tests · ✅ Checkov 20/0 · ✅ mutation check
- ⬜ **Not deployed to Azure yet.** No evidence exists yet, and `evidence/README.md` says so.

---

## 📅 2026-10-28 — Day 2: first real deployment + going hybrid

### Plot twist: the workload moves to my laptop

Decided not to run the workload as an Azure VM at all. Real companies have servers in their own
data centres, and the interesting question is *how does an on-prem box get an Azure secret without a
password on disk?* So: **VirtualBox VM on my laptop + Azure Arc**. Arc gives the box its own managed
identity. Same zero-trust design, now hybrid. And it's free.

### First contact with the real subscription 😬

- `az login` → `AADSTS50076`, MFA required. Plain `az login` silently skips MFA tenants. Needed
  `--tenant <id>` (+ `--use-device-code` because the browser pop-up hid). → **IA-2 is real**, nice.
- Subscription is **Pay-As-You-Go, spending limit OFF**. Nothing stops a bill. First thing I did:
  `$5 budget` with email alerts (`00-prereqs.sh`). The "free VM for 12 months" deal does *not* apply.
- Another resource group in the subscription already had spend this month → note to self: audit what else is running.

### Azure baseline: 14 resources, 19/19 checks on the first run ✅

What-if listed exactly 14 creates, deploy succeeded, `02-verify.sh` C1–C5 all PASS:
1 role / 1 secret scope, no privileged roles, RBAC mode, purge protection, firewall Deny + no bypass,
expiring secrets, AuditEvent + Activity Log exported.

### Building the on-prem server — three failures before it worked

| Try | What broke | Root cause | Fix |
|---|---|---|---|
| 1 | `PyCdlib.new() unexpected keyword 'interchange'` | wrong arg name | `interchange_level` |
| 2 | Seed ISO never attached → VM waited forever for network | Ubuntu OVA already has an IDE controller; VirtualBox allows one | attach to the existing controller |
| 3 | Kernel hung at "Loading essential drivers" for 15 min | **VT-x is owned by Windows' hypervisor**; VirtualBox fell back to the Hyper-V "NEM" backend, where SMP Linux boot hangs | **1 vCPU** → booted in 106 s |

Image supply chain: downloaded the Ubuntu cloud OVA, checked **SHA-256** *and* the **GPG signature**
of `SHA256SUMS` (Ubuntu key `D2EB…7C81`). Then verified hardening live: ufw default-deny, key-only SSH,
no root, fail2ban, auditd, unattended-upgrades, `intern` has no sudo.

### Arc onboarding

- Agent `1.69.03579.1568`, installer sha256 `a41c8b06…9101` (recorded).
- Connected with device code + MFA — **no service-principal secret ever existed**.
- `config.mode monitor` → no remote extensions / run-command / SSH-over-Arc. Azure can *see* the box,
  not *drive* it.
- Token dir `drwxr-x--- himds himds`. Only `ztapp` (the app's service account) was added to `himds`.

⚠️ First onboarding attempt died: `set: pipefail: invalid option name` → **CRLF line endings**.
Python on Windows had rewritten my files with `\r\n`; Git Bash tolerates that, real Linux doesn't.
Converted everything to LF and added a test… which first passed when it shouldn't (I read the file with
`read_text()`, which hides CRLF). Read bytes instead → drill caught it.
**→ note to self:** test the test, *every* time.

### App live

`curl http://192.168.56.10:8080/secret-check` → `length 36, sha256_12 ac00aabf4e6d`. Hashed the secret
from the admin side → **same hash**. systemd sandbox score **1.7 OK** (most services are 9+).

### Attack day 🗡️ (results in `evidence/2026-10-28/EVD-013-*`)

| ID | Expected | Got | Verdict |
|---|---|---|---|
| A01 insider → Arc token | Permission denied | Permission denied | ✅ held |
| A02 credential hunt | nothing found, environ unreadable | nothing found, environ unreadable | ✅ held |
| A03 SSRF → HIMDS | 401, no token | 401, no token… **but `file://` read the challenge key** | ⚠️ **F-005** |
| A04 root blast radius | 1 secret, rest 403 | 1 secret; decoy/list/write/delete/RG-read/Owner-grant/Graph all denied | ✅ held |
| A05 token replay | works from same IP | **200 from my laptop**, decoy still 403 | ⚠️ RISK-08 (accepted) |
| A06 brute force | banned | password not offered; unknown keys refused; **banned my own laptop** 😅 | ✅ held |
| A07 local privesc | denied + audited | no sudo; 6 `access_denied` audit records | ✅ held (after F-007 fix) |
| A08 re-test F-005 | all internal targets blocked | 8/8 blocked incl. `2130706433` & `[::1]`; example.com allowed | ✅ fixed |

Things **I** got wrong along the way (kept, because they're the real lessons):

- Expected `GET /resourcegroups` → 403. Azure **list** calls return **200 + only what you may see**
  (here: 0 items). Reading the RG directly → 403, granting Owner → 403. Fixed the probe to count items
  and added the Owner-escalation probe — the check that actually matters.
- Runner died silently twice: `[[ x ]] && warn` under `set -e`, and **curl exit 23** because
  `MSYS_NO_PATHCONV` stops Git Bash translating `/dev/null`. Added `$DEVNULL` and `set -E`.
- Debugged with `bash -x` once — **it echoed a live bearer token**. Never again: the ERR trap now prints
  line numbers only, and `redact()` masks JWTs.
- auditd showed 0 events → the `-w tokens -p r` watch never fires because `intern` is stopped at
  *entering* the dir. Added the CIS "unsuccessful access" rule (`exit=-EACCES`). Still 0… because
  `ausearch` over SSH reads **stdin** instead of the log. `--input-logs` → 6 events. Two bugs, one symptom.

### The detection lesson that surprised me

KQL showed every A04 denial (10 × 403 by the Arc identity). But the A05 replay from my laptop looks
**identical** to the server's own reads — same identity, same home IP. Behind a home NAT, neither the
firewall nor the logs can tell devices apart. That's RISK-08 with real data, and the reason companies use
Private Link / VPN / dedicated egress IPs.

## 📅 ____-__-__ — Day 3: policy, logs, break-it drills

- [ ] Policy report: ___ compliant / ___ non-compliant. Expected non-compliant: private link (RISK-01). Others?
- [ ] KQL: could I see my own 403s from the probe? Time from action → log: ____ min
- [ ] Alert email arrived for the RBAC drill? Delay: ____ min
- [ ] Drill 4: tried `az keyvault purge` → error message: ______

## 📅 ____-__-__ — Day 4: OIDC pipeline

- [ ] First run failed? (common: `AADSTS70021` = subject mismatch → check environment name)
- [ ] Tried granting Owner from the pipeline → denied with condition error? Paste the error (redacted):

> 

## Findings log

| # | Date | Finding | Severity | Root cause | Fix | Re-tested |
|---|---|---|---|---|---|---|
| F-001 | 2026-10-28 | Purge protection not statically verifiable (CKV_AZURE_110/42) | Medium | Conditional expression | Hard-coded `true` | ✅ Checkov 20/0 |
| F-002 | 2026-10-28 | Secret-scan regex missed `db_password` | Low | `\b` before underscore | Regex fixed | ✅ drill caught |
| F-003 | 2026-10-28 | Seed ISO not attached; VM booted unconfigured | Medium | OVA already has the only IDE controller | Reuse existing controller | ✅ VM rebuilt |
| F-004 | 2026-10-28 | Scripts failed on Linux (`pipefail` invalid) | Medium | CRLF written by Python on Windows | LF everywhere + byte-level test | ✅ drill caught |
| F-005 | 2026-10-28 | SSRF reads Arc challenge key via `file://` | **High** (token still blocked by header check) | No scheme/host allow-list | Scheme allow-list, resolve-then-block internal IPs, no redirects | ✅ A08 8/8 blocked + 11 unit tests |
| F-006 | 2026-10-28 | Probe expected 403 on ARM list | Low (test bug) | ARM filters list results | Count items; add Owner-escalation probe | ✅ |
| F-007 | 2026-10-28 | Denied token access not audited | Medium | Watch rule can't see denied traversal; `ausearch` read stdin | CIS EACCES rule + `--input-logs` | ✅ 6 events |
| F-008 | 2026-10-28 | Debug trace printed a bearer token | Medium (process) | `bash -x` | ERR trap prints line only; JWT redaction | ✅ |
| F-009 | 2026-10-28 | First GitHub CI run: Checkov + Gitleaks red | Low (no real leak) | SARIF file renamed by newer Checkov; Gitleaks flagged public role GUIDs + one CSV phrase | Upload `results/` dir; narrow `.gitleaks.toml` allow-list (2 public GUIDs); `.gitleaksignore` for 1 reviewed fingerprint; local leak drill still caught | ✅ CI 5/5 green |
| F-010 | 2026-10-28 | MCSB says Arc server lacks SSH-key auth & baseline | Low (visibility, not exposure) | Guest Configuration disabled by monitor mode → 0 reports → AuditIfNotExists = NonCompliant | Accepted as RISK-09; on-box evidence compensates | ✅ verified 0 GC assignments + `passwordauthentication no` |
| F-011 | 2026-10-28 | First OIDC deploy refused: `AADSTS700213` | Low (fail-closed) | GitHub now sends an **immutable-ID subject** (`repo:owner@<id>/repo@<id>:environment:lab`); credential trusted the legacy name-only form | Script reads `sub_claim_prefix` from GitHub's API; credential updated (stricter: survives renames, blocks re-created-repo takeover) | ✅ see deploy re-run |
| F-012 | | | | | | |
