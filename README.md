# Azure IAM Zero Trust Lab

## Objective

Design and validate a least-privilege Azure IAM pattern using a user-assigned managed
identity, RBAC, and Azure Key Vault without storing application credentials in source code.

## Why This Matters

This project demonstrates SC-500 skills recruiters expect to see beyond certification:
identity architecture, workload identity, least privilege, secrets handling, control mapping,
and evidence-driven validation.

## Threat Scenario

An attacker obtains application source code or environment variables. The application must
not contain reusable cloud credentials, and its identity must not have broad subscription access.

## Architecture

See `architecture.md`.

## Implementation

The Bicep template defines:
- user-assigned managed identity
- Key Vault using Azure RBAC
- resource-scoped role assignment
- public access settings as parameters

No deployment is required to validate the template locally with the Bicep compiler.

## Validation

```bash
az bicep build --file infra/main.bicep
python tests/test_design.py
```

If you have an Azure subscription, use a non-production lab resource group and save
real outputs under `evidence/`.

## Evidence To Collect

- Bicep build succeeds
- managed identity resource ID
- Key Vault RBAC mode
- role assignment scope
- proof that Owner/Contributor was not assigned
- redacted Azure CLI export

## Interview Talking Point

“I designed workload access around managed identity and resource-scoped RBAC so the
application does not depend on embedded credentials. I mapped and tested the design against
NIST AC-3, AC-6, IA-2/IA-5 concepts, and SC-28.”

## Status

- [x] Design
- [x] Static validation tests
- [ ] Azure execution
- [ ] Real evidence captured
