#!/bin/bash
# Runs INSIDE the probe VM via `az vm run-command invoke` (no SSH, no inbound port).
# Acts as the workload: gets tokens from IMDS for the user-assigned identity, then tries
# one allowed action and several forbidden ones. Secret values are NEVER printed -
# only their length and a short SHA-256 prefix so the admin can confirm it is the right secret.
#
# Args: CLIENT_ID VAULT_NAME SUBSCRIPTION_ID APP_SECRET DECOY_SECRET   (CLIENT_ID ignored on Arc servers)
# Works on Azure VMs (IMDS) and on Azure Arc-enabled on-prem servers (HIMDS on localhost:40342).
CLIENT_ID="$1"; VAULT="$2"; SUB="$3"; APP_SECRET="$4"; DECOY_SECRET="$5"; RG="${6:-rg-sc500-iam-zt-lab}"
KV="https://${VAULT}.vault.azure.net"
IMDS="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=${CLIENT_ID}"
OUT=/tmp/probe.out

ARC="http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01"

token() {
  if [ -S /var/opt/azcmagent/socks/himds.sock ] || curl -s -o /dev/null -m 2 "$ARC" ; then
    # Azure Arc (on-prem server): 401 challenge -> read key file (root/himds only) -> retry with it
    local realm key
    realm=$(curl -s -D - -o /dev/null -H Metadata:true "${ARC}&resource=$1" | grep -i '^WWW-Authenticate' | sed 's/.*realm=//' | tr -d '\r')
    key=$(cat "$realm" 2>/dev/null) || { echo ""; return; }
    curl -s -H Metadata:true -H "Authorization: Basic $key" "${ARC}&resource=$1"
  else
    # Azure VM: IMDS, user-assigned identity selected by client id
    curl -s -H Metadata:true "${IMDS}&resource=$1"
  fi | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null
}

summarise() {
  python3 - "$OUT" <<'PY'
import hashlib, json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("body=non-json"); sys.exit()
if isinstance(d.get("value"), str):
    v = d["value"]
    print("len=%d sha256_12=%s" % (len(v), hashlib.sha256(v.encode()).hexdigest()[:12]))
elif isinstance(d.get("value"), list):
    print("items=%d" % len(d["value"]))   # ARM list calls FILTER (200 + only what you may see)
elif "error" in d:
    e = d["error"]
    print("error=%s inner=%s" % (e.get("code", ""), (e.get("innererror") or {}).get("code", "")))
else:
    print("body=ok")
PY
}

probe() {  # name method url token [json-body]
  local code
  if [ -n "${5:-}" ]; then
    code=$(curl -s -m 20 -o "$OUT" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $4" \
           -H 'Content-Type: application/json' -d "$5" "$3")
  else
    code=$(curl -s -m 20 -o "$OUT" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $4" "$3")
  fi
  echo "PROBE $1 http=$code $(summarise)"
  rm -f "$OUT"
}

KV_TOKEN=$(token "https%3A%2F%2Fvault.azure.net")
ARM_TOKEN=$(token "https%3A%2F%2Fmanagement.azure.com%2F")
GRAPH_TOKEN=$(token "https%3A%2F%2Fgraph.microsoft.com")
[ -n "$KV_TOKEN" ] && echo "PROBE imds_token http=200" || echo "PROBE imds_token http=000"

# Allowed: the one secret the app needs
probe read_app_secret    GET    "${KV}/secrets/${APP_SECRET}?api-version=7.4"   "$KV_TOKEN"
# Forbidden: everything else
probe read_decoy_secret  GET    "${KV}/secrets/${DECOY_SECRET}?api-version=7.4" "$KV_TOKEN"
probe list_secrets       GET    "${KV}/secrets?api-version=7.4"                 "$KV_TOKEN"
probe write_secret       PUT    "${KV}/secrets/${APP_SECRET}?api-version=7.4"   "$KV_TOKEN" '{"value":"attacker-controlled"}'
probe delete_secret      DELETE "${KV}/secrets/${APP_SECRET}?api-version=7.4"   "$KV_TOKEN"
probe arm_list_rgs       GET    "https://management.azure.com/subscriptions/${SUB}/resourcegroups?api-version=2021-04-01" "$ARM_TOKEN"
probe arm_read_rg        GET    "https://management.azure.com/subscriptions/${SUB}/resourcegroups/${RG}?api-version=2021-04-01" "$ARM_TOKEN"
# Privilege escalation: try to make a role assignment of Owner on the resource group
probe arm_escalate_owner PUT    "https://management.azure.com/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Authorization/roleAssignments/$(cat /proc/sys/kernel/random/uuid)?api-version=2022-04-01" "$ARM_TOKEN"   "{\"properties\":{\"roleDefinitionId\":\"/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635\",\"principalId\":\"00000000-0000-0000-0000-000000000000\"}}"
probe graph_list_users   GET    "https://graph.microsoft.com/v1.0/users?\$top=1" "$GRAPH_TOKEN"
# Egress lockdown: arbitrary internet should be unreachable (http=000)
probe internet_egress    GET    "https://example.com" "none"
