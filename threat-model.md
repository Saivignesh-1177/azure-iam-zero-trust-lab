# Threat Model

## Assets
- identities
- cloud configuration
- sensitive application data
- security logs
- administrative interfaces

## Threat Actors
- external attacker
- compromised user
- malicious insider
- compromised workload identity
- misconfiguration / accidental exposure

## Method

Use a simple threat path:

`Threat Actor -> Entry Point -> Privilege / Action -> Protected Asset -> Control -> Evidence`

Document every tested scenario and map it to one or more controls.

## Primary Abuse Case

**Credential theft:** attacker reads repository or application configuration.

Mitigation:
- no reusable secret in source
- managed identity
- resource-scoped RBAC
- secrets stored in a dedicated secret store
