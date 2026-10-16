# Security Hardening Status

This branch carries the completed P0-P2 security hardening pass plus the P3 runtime control-plane hardening changes.

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

- Telemetry endpoints remain tenant-scoped and never expose evaluator reasoning.
- Evidence endpoints require an active human tenant session; API-key/dev-fallback principals cannot read the forensic surface.
- Approval payload persistence redacts credential keys plus common PII values recursively.
- Policy rule inputs use a controlled operation/decision vocabulary.
- A tenant can have only one active policy; activation is serialized by application logic and a database partial unique index.
- Production webhook destinations require HTTPS and reject private/loopback targets, including alternate numeric IPv4 spellings.

## P2 — operational hardening

- Production startup fails closed when PostgreSQL, the durable security control-plane dependency, is unavailable.
- Isolation uses explicit `isolation:execute` and `device:use` capabilities rather than ad-hoc capability strings.
- Browser navigation rejects localhost/private/link-local/reserved targets and alternate numeric IPv4 spellings unless explicitly overridden by policy.
- Presented authority headers are bounded by size and maximum chain length before parsing.
- Judge/provider exception details are not returned as security decision reasons.
- CI uses read-only repository permissions.
- CI compiles application/test code before the test phase.
- CI requires exactly one Alembic migration head.
- Security regression tests are maintained alongside the affected control boundaries.

## P3 — runtime control-plane hardening

- Runtime task reads require exact tenant + agent ownership; same-tenant agents cannot inspect each other's task records.
- Runtime task cancellation verifies ownership before invoking the scheduler, preventing cross-agent cancellation.
- Runtime session closure verifies exact agent ownership before mutating session state.
- Runtime task/session/workflow creation and control require the canonical `agent:invoke` capability.
- Missing or malformed runtime ownership metadata fails closed with non-enumerating 404 responses.
- Unexpected runtime/workflow submission exceptions return stable generic error codes instead of leaking backend/database exception details.
- Regression tests cover cross-agent task/session control, invocation capability enforcement, and unexpected error isolation.

## Non-goals

Future product integrations that are still explicit scaffolds (for example KMS/SAML/multi-region/event-bus adapters) are not treated as implemented security controls. They remain outside the runtime enforcement path until their owning feature phases are implemented.
