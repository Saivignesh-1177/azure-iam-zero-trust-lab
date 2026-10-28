#!/usr/bin/env python3
"""zt-app: the on-prem workload. Reads ONE secret from Azure Key Vault using the Azure Arc
managed identity of the server it runs on - no password, key, or connection string anywhere.

Stdlib only (no third-party packages = no dependency supply-chain risk).

Endpoints
  GET /health           liveness
  GET /secret-check     fetches the secret and returns its length + SHA-256 prefix (never the value)
  GET /fetch?url=...    DELIBERATELY VULNERABLE server-side fetch (SSRF), only when ZT_VULN_SSRF=1.
                        Used by attacks/a03-ssrf.sh to show why Arc's challenge-file design matters.

Config (environment, non-secret): ZT_VAULT_NAME, ZT_SECRET_NAME, ZT_PORT, ZT_VULN_SSRF
"""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VAULT = os.environ.get("ZT_VAULT_NAME", "")
SECRET = os.environ.get("ZT_SECRET_NAME", "app-db-password")
PORT = int(os.environ.get("ZT_PORT", "8080"))
VULN_SSRF = os.environ.get("ZT_VULN_SSRF") == "1"      # 1 = deliberately vulnerable /fetch (attack demo)
SSRF_GUARDED = os.environ.get("ZT_VULN_SSRF") == "2"   # 2 = the FIX for finding F-005 (OWASP SSRF cheat sheet)
# Azure Arc's local identity endpoint (HIMDS). Arc exports IDENTITY_ENDPOINT system-wide.
IDENTITY_ENDPOINT = os.environ.get("IDENTITY_ENDPOINT", "http://localhost:40342/metadata/identity/oauth2/token")

_cache: dict = {}


def log(event: str, **fields) -> None:
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}),
          flush=True)


def arc_token(resource: str) -> str:
    """Azure Arc token flow: 1st call returns 401 + a path to a key file only root/himds can read;
    2nd call proves local privilege by presenting that file's contents."""
    url = f"{IDENTITY_ENDPOINT}?api-version=2020-06-01&resource={urllib.parse.quote(resource, safe='')}"
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers={"Metadata": "true"}), timeout=5)
        raise RuntimeError("expected a 401 challenge from HIMDS")
    except urllib.error.HTTPError as e:
        challenge = e.headers.get("WWW-Authenticate", "")
        if e.code != 401 or "realm=" not in challenge:
            raise
    key_path = challenge.split("realm=", 1)[1].strip()
    with open(key_path) as f:          # PermissionError unless we're root or in the 'himds' group
        key = f.read().strip()
    req = urllib.request.Request(url, headers={"Metadata": "true", "Authorization": f"Basic {key}"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)["access_token"]


def read_secret() -> str:
    hit = _cache.get(SECRET)
    if hit and hit[1] > time.time():
        return hit[0]
    token = arc_token("https://vault.azure.net")
    req = urllib.request.Request(f"https://{VAULT}.vault.azure.net/secrets/{SECRET}?api-version=7.4",
                                 headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        value = json.load(r)["value"]
    _cache[SECRET] = (value, time.time() + 300)   # 5-minute cache: fewer vault calls, fast revocation
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):   # a redirect to 127.0.0.1 is a classic SSRF bypass
        return None


NO_REDIRECTS = urllib.request.build_opener(_NoRedirect)


def ssrf_reject_reason(url: str) -> str:
    """Return why a URL must not be fetched, or '' if it is safe (fix for F-005)."""
    import ipaddress
    import socket
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https"):
        return f"scheme '{parts.scheme}' not allowed"          # kills file://, gopher://, ...
    if not parts.hostname:
        return "no host"
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror:
        return "unresolvable host"
    for info in infos:                                          # check what the name RESOLVES to
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return f"destination {ip} is internal"              # kills localhost:40342, 169.254.169.254, 10/8 ...
    return ""


class Handler(BaseHTTPRequestHandler):
    server_version = "zt-app"
    sys_version = ""

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):   # route access logs through our JSON logger
        log("http", client=self.client_address[0], request=self.requestline, status=args[1] if len(args) > 1 else "")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path)
        if path.path == "/health":
            return self._send(200, {"status": "ok"})
        if path.path == "/secret-check":
            try:
                v = read_secret()
                return self._send(200, {"secret": SECRET, "length": len(v),
                                        "sha256_12": hashlib.sha256(v.encode()).hexdigest()[:12]})
            except Exception as e:  # noqa: BLE001 - report the class, never the details or the value
                log("secret_error", error=type(e).__name__, detail=str(e)[:200])
                return self._send(502, {"error": type(e).__name__})
        if path.path == "/fetch" and SSRF_GUARDED:
            target = urllib.parse.parse_qs(path.query).get("url", [""])[0]
            reason = ssrf_reject_reason(target)
            log("fetch_guarded", target=target, client=self.client_address[0], blocked=reason or "")
            if reason:
                return self._send(400, {"error": "blocked", "reason": reason})
            try:
                with NO_REDIRECTS.open(urllib.request.Request(target), timeout=5) as r:
                    return self._send(200, {"status": r.status, "body": r.read(400).decode(errors="replace")})
            except Exception as e:  # noqa: BLE001
                return self._send(502, {"error": type(e).__name__})
        if path.path == "/fetch" and VULN_SSRF:
            target = urllib.parse.parse_qs(path.query).get("url", [""])[0]
            log("ssrf_fetch", target=target, client=self.client_address[0])
            try:
                # Mimics a typical SSRF bug: attacker controls the URL, server adds "helpful" headers.
                req = urllib.request.Request(target, headers={"Metadata": "true"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    return self._send(200, {"status": r.status, "body": r.read(400).decode(errors="replace")})
            except urllib.error.HTTPError as e:
                return self._send(200, {"status": e.code, "www_authenticate": e.headers.get("WWW-Authenticate"),
                                        "body": e.read(400).decode(errors="replace")})
            except Exception as e:  # noqa: BLE001
                return self._send(200, {"error": type(e).__name__, "detail": str(e)[:200]})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    if not VAULT:
        sys.exit("ZT_VAULT_NAME is not set")
    log("start", port=PORT, vault=VAULT, secret=SECRET, vuln_ssrf=VULN_SSRF)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
