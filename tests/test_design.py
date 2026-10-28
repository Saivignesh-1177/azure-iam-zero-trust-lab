"""Static security tests for infra/main.bicep (run before anything is deployed).

Each test names the NIST SP 800-53 control and threat ID it guards, so a failing test
points straight at the risk it re-opens.
"""
import json

from conftest import of_type

KV_SECRETS_USER = "4633458b-17de-408a-b874-0445c86b69e6"
KV_SECRETS_OFFICER = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
PRIVILEGED_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "00482a5a-887f-4fb3-b363-3b7ba9cee11b": "Key Vault Administrator",
}


def single(resources, rtype):
    found = of_type(resources, rtype)
    assert len(found) == 1, f"expected exactly one {rtype}, found {len(found)}"
    return found[0]


# --- Identity & least privilege -------------------------------------------------------------

def test_workload_uses_user_assigned_managed_identity(resources):
    """IA-9, IA-5 / T01: the workload authenticates as a managed identity, not with a secret."""
    single(resources, "Microsoft.ManagedIdentity/userAssignedIdentities")


def role_assignments(resources, resolve):
    """(roleDefinitionId, scope, resource) with ARM variables resolved."""
    return [(resolve(ra["properties"]["roleDefinitionId"]), resolve(ra.get("scope", "")), ra)
            for ra in of_type(resources, "Microsoft.Authorization/roleAssignments")]


def test_no_privileged_role_is_ever_assigned(resources, resolve):
    """AC-6 / T03, T04: nothing in the template hands out Owner, Contributor or delegation rights."""
    for role, _, ra in role_assignments(resources, resolve):
        role = role.lower()
        for guid, name in PRIVILEGED_ROLES.items():
            assert guid not in role, f"{name} assigned by {ra.get('name')}"


def test_only_expected_key_vault_roles(resources, resolve):
    """AC-6: workload gets Secrets User; the human admin gets Secrets Officer on the vault only."""
    roles = [role for role, _, _ in role_assignments(resources, resolve)]
    assert len(roles) == 3, "cloud MI + Arc server (Secrets User) and admin (Secrets Officer)"
    assert sum(KV_SECRETS_USER in r for r in roles) == 2
    assert sum(KV_SECRETS_OFFICER in r for r in roles) == 1


def test_workload_role_is_scoped_to_a_single_secret(resources, resolve):
    """AC-6 / T03: every workload grant (cloud VM and on-prem Arc server) is scoped to ONE secret."""
    workload = [(scope, ra) for role, scope, ra in role_assignments(resources, resolve) if KV_SECRETS_USER in role]
    assert len(workload) == 2
    for scope, ra in workload:
        assert "Microsoft.KeyVault/vaults/secrets" in scope, f"workload role scope is not a single secret: {scope!r}"
        assert "'app-db-password'" in scope
        assert ra["properties"]["principalType"] == "ServicePrincipal"


def test_admin_role_is_vault_scoped_and_optional(resources, resolve):
    """AC-6(1) / T15: the admin is not given subscription/RG-wide data-plane rights."""
    admin = [(scope, ra) for role, scope, ra in role_assignments(resources, resolve) if KV_SECRETS_OFFICER in role]
    assert len(admin) == 1
    scope, ra = admin[0]
    assert "'Microsoft.KeyVault/vaults'" in scope and "secrets" not in scope
    assert "condition" in ra, "admin role should only deploy when adminPrincipalId is supplied"


# --- Key Vault hardening ----------------------------------------------------------------------

def test_key_vault_uses_rbac_not_access_policies(resources):
    """AC-3: Azure RBAC is the single authorization model; legacy access policies are not used."""
    props = single(resources, "Microsoft.KeyVault/vaults")["properties"]
    assert props["enableRbacAuthorization"] is True
    assert "accessPolicies" not in props or props["accessPolicies"] == []


def test_key_vault_is_recoverable(resources):
    """CP-10 / T06: soft delete + purge protection - not even an Owner can destroy secrets instantly."""
    props = single(resources, "Microsoft.KeyVault/vaults")["properties"]
    assert props["enableSoftDelete"] is True
    assert props["enablePurgeProtection"] is True
    assert props["softDeleteRetentionInDays"] >= 7


def test_key_vault_firewall_default_deny(resources):
    """SC-7 / T05: data plane is closed by default, with no trusted-services bypass."""
    acls = single(resources, "Microsoft.KeyVault/vaults")["properties"]["networkAcls"]
    assert acls["defaultAction"] == "Deny"
    assert acls["bypass"] == "None"


def test_key_vault_least_functionality(resources):
    """CM-7: VM/ARM/disk-encryption integrations that could pull secrets are switched off."""
    props = single(resources, "Microsoft.KeyVault/vaults")["properties"]
    for flag in ("enabledForDeployment", "enabledForTemplateDeployment", "enabledForDiskEncryption"):
        assert props[flag] is False, flag


def test_secrets_expire_and_have_content_type(resources):
    """IA-5 / T13: every secret has an expiry and a content type (Azure Policy audits both)."""
    secrets = of_type(resources, "Microsoft.KeyVault/vaults/secrets")
    assert len(secrets) == 2
    for s in secrets:
        assert "exp" in s["properties"]["attributes"]
        assert s["properties"]["contentType"]


def test_secret_values_come_from_secure_parameters(arm, resources):
    """IA-5(7) / T01: secret values are generated secure parameters, never literals in the template."""
    for s in of_type(resources, "Microsoft.KeyVault/vaults/secrets"):
        value = s["properties"]["value"]
        assert value.startswith("[parameters("), f"secret value is not a parameter: {value!r}"
        param = value.split("'")[1]
        assert arm["parameters"][param]["type"] == "securestring"


def test_outputs_never_expose_secret_values(arm):
    """IA-5 / T01: deployment outputs are visible to Readers, so they hold identifiers only."""
    blob = json.dumps(arm.get("outputs", {})).lower()
    assert "secretvalue" not in blob
    assert "listkeys" not in blob and "listsecrets" not in blob


# --- Logging & detection ----------------------------------------------------------------------

def test_key_vault_audit_logs_go_to_log_analytics(resources):
    """AU-2, AU-12 / T08: every secret read/denial is recorded with caller identity and IP."""
    diag = single(resources, "Microsoft.Insights/diagnosticSettings")
    cats = [l.get("category") for l in diag["properties"]["logs"] if l["enabled"]]
    assert "AuditEvent" in cats
    single(resources, "Microsoft.OperationalInsights/workspaces")


def test_tamper_alerts_cover_escalation_destruction_and_blinding(bicep_text):
    """SI-4, AC-6(9) / T04, T06, T07: free activity-log alerts on the operations attackers use."""
    for op in ("roleAssignments/write", "roleAssignments/delete", "vaults/delete",
               "diagnosticSettings/delete"):
        assert op in bicep_text, f"no alert for {op}"


def test_log_ingestion_is_capped_for_free_tier(resources):
    """Cost guard-rail: daily cap keeps the workspace inside the 5 GB/month free allowance."""
    ws = single(resources, "Microsoft.OperationalInsights/workspaces")
    assert "dailyQuotaGb" in ws["properties"]["workspaceCapping"]


# --- Optional probe VM --------------------------------------------------------------------------

def test_no_public_ip_anywhere(resources):
    """SC-7, CM-7 / T11: nothing in the lab is reachable from the internet."""
    assert not of_type(resources, "Microsoft.Network/publicIPAddresses")
    nic = single(resources, "Microsoft.Network/networkInterfaces")
    for cfg in nic["properties"]["ipConfigurations"]:
        assert "publicIPAddress" not in cfg["properties"]


def test_vm_hardening(resources):
    """IA-2, SC-7 / T11: SSH keys only, user-assigned identity only, Trusted Launch."""
    vm = single(resources, "Microsoft.Compute/virtualMachines")
    assert vm["identity"]["type"] == "UserAssigned"
    linux = vm["properties"]["osProfile"]["linuxConfiguration"]
    assert linux["disablePasswordAuthentication"] is True
    sec = vm["properties"]["securityProfile"]
    assert sec["securityType"] == "TrustedLaunch"
    assert sec["uefiSettings"]["secureBootEnabled"] is True


def test_nsg_denies_all_inbound(bicep_text):
    """SC-7 / T11: explicit deny-all inbound overrides Azure's default AllowVnetInBound."""
    assert "'deny-all-inbound'" in bicep_text
    assert "'deny-internet-outbound'" in bicep_text


def test_subnet_uses_key_vault_service_endpoint(resources):
    """SC-7 / T05: the vault trusts the workload subnet by name, not by public IP."""
    vnet = single(resources, "Microsoft.Network/virtualNetworks")
    endpoints = vnet["properties"]["subnets"][0]["properties"]["serviceEndpoints"]
    assert {"service": "Microsoft.KeyVault"} in endpoints
