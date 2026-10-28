import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _bicep_command(path: Path) -> list[str] | None:
    """Prefer a standalone bicep binary, then the copy the Azure CLI installs, then `az bicep`."""
    standalone = shutil.which("bicep") or (
        str(Path.home() / ".azure" / "bin" / "bicep.exe")
        if (Path.home() / ".azure" / "bin" / "bicep.exe").exists()
        else None
    ) or (
        str(Path.home() / ".azure" / "bin" / "bicep")
        if (Path.home() / ".azure" / "bin" / "bicep").exists()
        else None
    )
    if standalone:
        return [standalone, "build", str(path), "--stdout"]
    az = shutil.which("az")
    if az:
        return [az, "bicep", "build", "--file", str(path), "--stdout"]
    return None


@pytest.fixture(scope="session")
def bicep_text() -> str:
    return (ROOT / "infra" / "main.bicep").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def arm() -> dict:
    """infra/main.bicep compiled to ARM JSON - tests assert on what Azure will actually receive."""
    cmd = _bicep_command(ROOT / "infra" / "main.bicep")
    if cmd is None:
        pytest.skip("Bicep compiler not found (az bicep install)")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, f"bicep build failed:\n{result.stderr}"
    return json.loads(result.stdout)


@pytest.fixture(scope="session")
def resources(arm) -> list[dict]:
    res = arm["resources"]
    return list(res.values()) if isinstance(res, dict) else res


def of_type(resources: list[dict], rtype: str) -> list[dict]:
    return [r for r in resources if r["type"].lower() == rtype.lower()]


@pytest.fixture(scope="session")
def resolve(arm):
    """Inline literal `variables('x')` references so assertions see real role GUIDs and names."""
    import re

    def _resolve(value: str) -> str:
        def sub(m):
            v = arm.get("variables", {}).get(m.group(1))
            return f"'{v}'" if isinstance(v, str) and not v.startswith("[") else m.group(0)
        return re.sub(r"variables\('([^']+)'\)", sub, value)

    return _resolve
