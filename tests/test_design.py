from pathlib import Path

bicep = Path("infra/main.bicep").read_text().lower()

assert "userassignedidentities" in bicep
assert "enablerbacauthorization: true" in bicep
assert "roleassignments" in bicep
assert "4633458b-17de-408a-b874-0445c86b69e6" in bicep
assert "'owner'" not in bicep
assert "'contributor'" not in bicep

print("PASS: IAM design uses managed identity, RBAC-enabled Key Vault, and scoped secret access.")
