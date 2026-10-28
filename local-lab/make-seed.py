"""Build a cloud-init NoCloud seed ISO (volume label CIDATA) for the VirtualBox VM.

usage: python local-lab/make-seed.py <ssh-public-key-file> <output.iso> [hostname]
needs: pip install pycdlib
"""
import io
import sys
from pathlib import Path

import pycdlib

HERE = Path(__file__).resolve().parent


def build(pubkey_file: str, out_iso: str, hostname: str = "zt-app-01") -> None:
    pubkey = Path(pubkey_file).read_text().strip()
    if "PRIVATE KEY" in pubkey:
        sys.exit("refusing: that is a private key")
    user_data = (HERE / "cloud-init" / "user-data.yaml").read_text()
    user_data = user_data.replace("__SSH_PUBKEY__", f'"{pubkey}"').replace("zt-app-01", hostname)
    files = {
        "user-data": user_data,
        "meta-data": f"instance-id: {hostname}-v1\nlocal-hostname: {hostname}\n",
        "network-config": (HERE / "cloud-init" / "network-config.yaml").read_text(),
    }
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="CIDATA")
    for name, text in files.items():
        data = text.replace("\r\n", "\n").encode()
        short = name.replace("-", "").upper()[:8]
        iso.add_fp(io.BytesIO(data), len(data), f"/{short}.;1", rr_name=name, joliet_path=f"/{name}")
    iso.write(out_iso)
    iso.close()
    print(f"seed ISO written: {out_iso}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    build(*sys.argv[1:4])
