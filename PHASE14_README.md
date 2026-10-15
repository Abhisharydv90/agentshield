# AURAGENT — Phase 14 Enterprise

Phase 14 adds enterprise governance around the existing AURAGENT security,
evidence, runtime, ecosystem and scale fabrics.

## Scope

- SAML enterprise SSO trust metadata
- organization-wide security policy
- evidence/audit retention
- legal hold
- SIEM/SOC export contract
- KMS/HSM key descriptor and rotation contract
- compliance control/evidence manifests
- tenant security posture

## SSO boundary

This phase does not implement an unsafe custom SAML parser.

It validates the enterprise trust configuration and produces a deterministic
trust-binding digest. Actual assertion processing must be performed by a
hardened standards-compliant identity provider/library with signature,
issuer, audience, replay, certificate and clock validation.

SSO authentication does not create or increase agent authority.

## Retention

Retention is explicit and tenant scoped. Legal hold causes expiry calculations
to return no deletion deadline.

Actual deletion remains owned by the durable subsystem that stores the records,
so Phase 14 does not create another persistence system.

## SIEM/SOC

The enterprise SIEM boundary accepts only redacted security events and enforces:

- tenant equality
- HTTPS endpoint
- bounded batch size
- bounded payload size

Actual network delivery should use the Phase 7 network egress boundary and,
for production, a durable queue.

## Key management

Only key descriptors are represented. No raw private/public key bytes are
stored by this layer.

The included in-memory provider exists only as a deterministic development
reference. Production deployments should bind the same interface to KMS/HSM.

## Compliance

Controls are explicit objects with evidence requirements. A compliance package
hash binds together:

`organization + framework + controls + available evidence + evidence count`

This does not make unsupported compliance claims automatically true; it creates
an auditable package manifest from the evidence actually supplied.

## Organization-wide policy

Enterprise policies constrain actions in addition to the Trust Kernel. They
never create authority.

Examples:

- mandatory SSO
- region allowlists/denylists
- high-risk human approval
- evidence-required actions
- signed ecosystem requirement

## Persistence

Phase 14 intentionally adds no Alembic migration. It composes existing
tenant, evidence, runtime and control-plane primitives.

Durable enterprise configuration can be bound to existing organization settings
or a later enterprise persistence layer without changing the contracts.

## Router integration

The AURAGENT composition root already discovers:

`app.api.enterprise`

No rewrite of `main.py` is required.

## Verification policy

The installer does not execute the final complete backend/frontend/E2E suite.
Per project process, verification happens after Phase 15 is complete.
