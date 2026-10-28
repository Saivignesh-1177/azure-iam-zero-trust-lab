"""Mask every GUID in a file (app ids, object ids, correlation ids) EXCEPT built-in role
definition ids, which are public and identical in every tenant. Used by lib.sh redact()."""
import re
import sys

KEEP = {
    "4633458b-17de-408a-b874-0445c86b69e6",  # Key Vault Secrets User
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",  # Key Vault Secrets Officer
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168",  # Role Based Access Control Administrator
    "acdd72a7-3385-48ef-bd42-f606fba81ae7",  # Reader
    "00000000-0000-0000-0000-000000000000",
}
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

for path in sys.argv[1:]:
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    text = GUID.sub(lambda m: m.group(0) if m.group(0).lower() in KEEP else "<GUID>", text)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
