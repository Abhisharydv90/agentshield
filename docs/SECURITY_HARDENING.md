# Security Hardening Status

This branch contains the completed P0-P2 security hardening pass for AgentShield.

## P0 — critical enforcement

### P0-1 MCP/A2A authorization boundary
MCP and A2A transports are authorized through the Tool Fabric before network I/O. The route URL is server-configured and cannot be replaced by a request payload.

### P0-2 isolation execution ownership
Isolation run lookup and stop operations are tenant-and-agent scoped. Execution IDs are not sufficient to access or stop another agent's run.

### P0-3 authority-token delegation
Authority tokens are validated as a root-to-leaf chain. Delegated tokens require the parent token hash, parent-subject signer binding, tenant/policy binding, authority conservation, bounded expiry, and bounded delegation depth. Final subject authority is also checked against the subject agent ceiling.

### P0-4 canonical outbound authorization
Signed authority context is propagated into both streaming and non-streaming outbound tool authorization paths so they converge on the same Security Decision Engine.

## P1 — high-priority data and policy hardening

- Telemetry responses no longer expose evaluator reasoning.
- Approval payload persistence redacts credential and common PII fields recursively.
- Policy rule inputs use a controlled operation/decision vocabulary.
- A tenant can have only one active policy; activation is serialized by application logic and a database partial unique index.
- Production webhook destinations require HTTPS and reject private/loopback targets, including alternate numeric IPv4 spellings.

## P2 — operational hardening

- Production startup fails closed when PostgreSQL, the durable security control-plane dependency, is unavailable.
- CI uses read-only repository permissions.
- CI compiles application/test code before the test phase.
- CI verifies that the Alembic migration graph has a head using cross-platform migration paths.
- Security regression tests are maintained alongside the affected control boundaries.

## Non-goals

Future product integrations that are still explicit scaffolds (for example KMS/SAML/multi-region/event-bus adapters) are not treated as implemented security controls. They remain outside the runtime enforcement path until their owning feature phases are implemented.
