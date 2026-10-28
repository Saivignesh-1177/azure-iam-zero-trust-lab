#!/usr/bin/env bash
# Shared helpers. Source this file from the other scripts; do not run it directly.
# Works in Azure Cloud Shell (recommended, free) and in Git Bash on Windows.
set -Eeuo pipefail   # -E: the ERR trap also fires inside functions
# On failure report WHERE, never the command text (it can contain bearer tokens). Never debug with `bash -x`.
trap 'echo "error: ${BASH_SOURCE[0]##*/} line $LINENO exited $?" >&2' ERR

export MSYS_NO_PATHCONV=1               # stop Git Bash rewriting /subscriptions/... into C:/...
# ...which also stops it translating /dev/null for native Windows tools (curl exit 23). Use $DEVNULL on the host.
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then DEVNULL=NUL; else DEVNULL=/dev/null; fi
export AZURE_CORE_ONLY_SHOW_ERRORS=true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"                              # every path below is relative to the repo root
STATE=".state"                          # gitignored: outputs, keys, raw (unredacted) exports
mkdir -p "$STATE"

: "${RG:=rg-sc500-iam-zt-lab}"
: "${LOCATION:=eastus}"
: "${DEPLOYMENT:=zt-main}"

FAILURES=0
log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*"; }

# az on Windows prints CRLF; strip it so captured values compare cleanly.
azq() { az "$@" | tr -d '\r'; }

# python3 on Windows is often a Microsoft Store stub that fails; fall back to python.
if python3 -c "" >/dev/null 2>&1; then PY=python3; else PY=python; fi

require_login() {
  az account show >/dev/null 2>&1 || { echo "Not logged in. Run: az login"; exit 1; }
  SUB_ID="$(azq account show --query id -o tsv)"
  TENANT_ID="$(azq account show --query tenantId -o tsv)"
  RG_ID="/subscriptions/$SUB_ID/resourceGroups/$RG"
}

# Loads OUT_<name> variables written by 01-deploy.sh.
load_outputs() {
  [[ -f "$STATE/env.sh" ]] || { echo "No $STATE/env.sh - run scripts/01-deploy.sh first"; exit 1; }
  # shellcheck disable=SC1091
  source "$STATE/env.sh"
}

# Replace tenant-identifying values before anything goes into evidence/.
redact() {
  local f="$1"
  local -a pairs=(
    "${SUB_ID:-}:<SUBSCRIPTION_ID>"
    "${TENANT_ID:-}:<TENANT_ID>"
    "${OUT_identityPrincipalId:-}:<MI_PRINCIPAL_ID>"
    "${OUT_identityClientId:-}:<MI_CLIENT_ID>"
    "${ADMIN_OID:-}:<ADMIN_OBJECT_ID>"
    "${GH_APP_ID:-}:<GITHUB_OIDC_APP_ID>"
    "${GH_SP_OID:-}:<GITHUB_OIDC_SP_ID>"
    "${MY_IP:-}:<ADMIN_PUBLIC_IP>"
    "${ARC_PRINCIPAL_ID:-}:<ARC_SERVER_PRINCIPAL_ID>"
  )
  local p
  for p in "${pairs[@]}"; do
    local value="${p%%:*}" token="${p#*:}"
    [[ -n "$value" ]] && sed -i "s/${value//./\\.}/${token}/gI" "$f"
  done
  # Bearer tokens (JWTs) - never publish one, even expired
  sed -i -E 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/<JWT_REDACTED>/g' "$f"
  # Catch-all: mask any other GUID except public built-in role ids
  "$PY" scripts/redact_guids.py "$f"
  # Email addresses
  sed -i -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<EMAIL>/g' "$f"
}

summary() {
  echo
  if [[ "$FAILURES" -eq 0 ]]; then
    printf '\033[1;32mALL CHECKS PASSED\033[0m\n'
  else
    printf '\033[1;31m%s CHECK(S) FAILED\033[0m - record them as findings, do not edit them away.\n' "$FAILURES"
  fi
  return "$FAILURES"
}
