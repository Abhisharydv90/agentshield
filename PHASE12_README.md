# AURAGENT — Phase 12 Ecosystem

Phase 12 is the interoperability and ecosystem layer of AURAGENT.

## Scope

It establishes stable contracts for:

- SDKs
- plugins
- MCP servers
- A2A peers
- enterprise/community integrations
- ecosystem registry discovery

## Important boundary

The ecosystem registry is **not** an authority store.

Registration means:

`known descriptor != trusted authority`

A registered plugin, MCP server or A2A peer does not receive:

- agent capabilities
- tool permissions
- filesystem access
- network egress
- secrets
- authority grants

Those remain controlled by the Trust Kernel, Tool Fabric, Memory Fabric and
Isolation Fabric.

## Plugin model

Phase 12 validates plugin metadata and canonical content hashes. It does not
load or execute arbitrary plugin code.

Actual tool execution remains inside Phase 5 Tool Fabric and, where required,
Phase 7 Isolation Fabric.

## MCP model

MCP entries are server descriptors only. Endpoint URLs must use HTTPS and
cannot contain credentials. Actual invocation remains behind the existing
MCP/Tool Fabric boundary.

## A2A model

A2A peers are descriptors. A peer's self-declared capabilities are treated as
claims, not authority.

Actual cross-agent delegation must remain inside the Phase 4 Trust Kernel
delegation/conservation model.

## SDK model

The Python SDK is intentionally thin and HTTPS-only. It constructs server API
requests and does not implement local authority decisions.

## Integration model

Integrations use explicit outbound domain patterns and server-side secret
references. No credential material is put into ecosystem manifests.

## Registry persistence

Phase 12 uses a process-local reference registry. This is deliberate: the
contract is stable while durable distributed/community registry persistence
belongs to later scale/enterprise work.

No new Alembic migration is added here.

## API

The AURAGENT composition root is already designed to discover:

`app.api.ecosystem`

Therefore Phase 12 does not require a rewrite of `main.py`.

## Verification

The installer does not execute the final full backend/frontend/E2E suite.
AURAGENT policy remains: implement Phases 0–15 first, then run one
comprehensive final verification pass.
