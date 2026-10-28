"""Repository hygiene: no credentials in the repo, CI cannot leak them, probes never print secrets.

Gitleaks does the deep scan in CI; these are fast local guard-rails (IA-5(7), T01, T09, T10).
"""
import re
import subprocess

import pytest
from conftest import ROOT

SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "storage account key": re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    "Entra client secret": re.compile(r"\b[A-Za-z0-9_~.]{3}8Q~[A-Za-z0-9_~.-]{31,34}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "SAS signature": re.compile(r"[?&]sig=[A-Za-z0-9%]{40,}"),
    "hard-coded password": re.compile(r"(?i)(password|passwd|client_secret)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
}


def tracked_text_files():
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    for rel in out:
        path = ROOT / rel
        if path.suffix in {".png", ".jpg", ".pdf"} or not path.is_file() or path.name == "test_repo_hygiene.py":
            continue
        yield rel, path.read_text(encoding="utf-8", errors="ignore")


def test_no_credentials_in_repository():
    hits = [f"{rel}: {name}" for rel, text in tracked_text_files()
            for name, rx in SECRET_PATTERNS.items() if rx.search(text)]
    assert not hits, "possible credentials committed:\n" + "\n".join(hits)


def test_local_state_is_gitignored():
    ignore = (ROOT / ".gitignore").read_text()
    for entry in (".state/", ".env", "*.pem", "*.key", "params.json"):
        assert entry in ignore, f"{entry} missing from .gitignore"


def test_ci_has_no_azure_credentials_and_read_only_token():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "permissions:\n  contents: read" in ci
    assert "id-token: write" not in ci, "CI (which runs on PRs) must not be able to mint Azure tokens"
    assert "azure/login" not in ci


def test_deploy_uses_oidc_manual_trigger_and_environment():
    deploy = (ROOT / ".github" / "workflows" / "deploy.yml").read_text()
    assert "workflow_dispatch" in deploy and "pull_request" not in deploy
    assert "environment: lab" in deploy
    assert "id-token: write" in deploy
    assert "client-secret" not in deploy and "creds:" not in deploy, "use OIDC, not a stored secret"
    # GitHub secrets are allowed ONLY for identifiers that must be masked in public logs - never a credential.
    import re
    used = set(re.findall(r"secrets\.([A-Z_]+)", deploy))
    assert used <= {"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "KV_ALLOWED_IPS"}, used


def test_probe_never_prints_secret_values():
    probe = (ROOT / "scripts" / "vm" / "probe.sh").read_text()
    assert "sha256" in probe
    assert "print(v)" not in probe and 'print(d["value"])' not in probe
    assert "cat $OUT" not in probe and 'cat "$OUT"' not in probe


def test_linux_files_use_lf_line_endings():
    """Scripts that run on Linux break with CRLF ('set: pipefail: invalid option name')."""
    bad = [rel for rel, _ in tracked_text_files()
           if rel.endswith((".sh", ".service", ".yaml", ".yml", ".kql", ".py", ".bicep"))
           and b"\r\n" in (ROOT / rel).read_bytes()]   # read bytes: read_text() would hide CRLF
    assert not bad, "CRLF line endings in: " + ", ".join(bad)
