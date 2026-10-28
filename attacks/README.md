# Attack Scenarios (adversary emulation)

Run from the laptop: `./attacks/run-attacks.sh` (all) or `./attacks/run-attacks.sh a03` (one).
Each prints **PASS** when the control held and **FAIL/WARN FINDING** when it didn't. The transcript
goes to `.state/attacks-*.txt` and becomes evidence **EVD-013** via `scripts/04-evidence.sh`.

> Only attack systems you own. Everything here targets your own VirtualBox VM and your own vault.

| ID | Scenario | Attacker starts as | ATT&CK | Threat | Expected outcome | Control(s) |
|---|---|---|---|---|---|---|
| A01 | Insider asks Arc for the machine's token | `intern` (no sudo) | T1528 | T16 | 401 challenge visible, key file **Permission denied**, no token | AC-6, IA-9 |
| A02 | Hunt for credentials on disk / in the app's memory | `intern` | T1552.001, T1552.007 | T01 | No credential exists; `/proc/<pid>/environ` unreadable | IA-5(7) |
| A03 | **SSRF** → identity endpoint (OWASP A10) | Anonymous HTTP client on the lab network | T1190 → T1528 | T17 | HIMDS returns 401; attacker can't set `Authorization` → no token. Watch for the `file://` finding | SI-10, SC-7 |
| A04 | Assume breach: **root** on the server — blast radius | `ztadmin` + sudo | T1555.006, T1098.003 | T03, T04 | 1 secret readable (by design); decoy, list, write, delete, ARM, Graph all **403** | AC-6, AC-6(10) |
| A05 | Steal the token and replay it elsewhere | root → laptop | T1528, T1550.001 | T02 | **Works from the same home IP (finding RISK-08)**; decoy still 403; fails from Cloud Shell (manual) | SC-7, AU-6 |
| A06 | SSH brute force / unknown keys | Laptop on the lab network | T1110 | T11 | Password auth not offered; fail2ban bans the source | AC-7, IA-2 |
| A07 | Local privilege escalation attempts | `intern` | T1548.003 | T16 | No sudo; attempts recorded by auditd | AC-6, AU-12 |

## Detect what you just did

After a run, give logs 5–15 minutes, then:

```bash
source .state/env.sh
az monitor log-analytics query -w $OUT_workspaceCustomerId --timespan PT2H -o table \
  --analytics-query "$(cat queries/kv-denied-access.kql)"          # A04/A05 403s, by identity + IP
az monitor log-analytics query -w $OUT_workspaceCustomerId --timespan PT2H -o table \
  --analytics-query "$(cat queries/kv-secret-reads-by-identity.kql)" # who read app-db-password, from where

# On the server
ssh ... ztadmin@192.168.56.10 "sudo ausearch --input-logs -k access_denied -ua intern -i | tail; sudo fail2ban-client status sshd; sudo journalctl -u zt-app --since -1h | grep ssrf_fetch"
```

## Write-up template (one per scenario, in `docs/lab-journal.md`)

| Field | |
|---|---|
| Hypothesis | "A low-privilege user cannot obtain the server's Azure token." |
| Steps | (commands) |
| Observed | (paste redacted output) |
| Verdict | Control held / Finding |
| Detection | Which log showed it? How long until it appeared? |
| Fix / follow-up | |
