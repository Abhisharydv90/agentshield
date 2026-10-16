# AURAGENT Phase 1 — Agent Development & Management

Phase 1 turns the existing Agent identity into a usable management plane.

## Implemented

- tenant-scoped agent CRUD
- immutable agent versions with content hashes
- draft/publish/revoke version lifecycle
- reusable tenant-scoped agent templates
- template-based agent creation
- explicit agent lifecycle transitions
- bounded capability configuration using the existing controlled vocabulary
- deployment declarations bound to an immutable published agent version
- tenant-scoped agent team membership
- admin/owner management with member read access

## Authority boundary

Phase 1 is a management plane. It does not mint delegated authority tokens and
does not execute workloads itself. Runtime actions continue through the Phase 2,
Phase 4, Phase 5 and Phase 7 enforcement boundaries.

Changing an agent's capabilities through this API creates an immutable version
record and only changes the active runtime capability set when that version is
published.

## Operational distinction

A deployment record expresses desired control-plane state. It does not claim
that the workload is actually running; runtime/execution status is owned by the
Phase 2 runtime and Phase 7 isolation layers.
