"""Regression tests for finding F-005: the SSRF guard in app/zt_app.py (SI-10, OWASP A10)."""
import importlib.util

import pytest
from conftest import ROOT

spec = importlib.util.spec_from_file_location("zt_app", ROOT / "app" / "zt_app.py")
zt_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(zt_app)


@pytest.mark.parametrize("url", [
    "file:///var/opt/azcmagent/tokens/x.key",                 # the original F-005 vector
    "gopher://localhost:40342/",
    "http://localhost:40342/metadata/identity/oauth2/token",  # Arc HIMDS
    "http://127.0.0.1:40342/",
    "http://2130706433:40342/",                               # 127.0.0.1 as a decimal integer
    "http://[::1]:40342/",
    "http://169.254.169.254/metadata/instance",               # Azure IMDS
    "http://10.0.2.2/", "http://192.168.56.1/",               # private ranges
    "http:///nohost",
])
def test_internal_or_non_http_targets_are_rejected(url):
    assert zt_app.ssrf_reject_reason(url), f"should be blocked: {url}"


def test_public_ip_literal_is_allowed():
    assert zt_app.ssrf_reject_reason("https://93.184.215.14/") == ""
