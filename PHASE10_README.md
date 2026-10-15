# AURAGENT — Phase 10 Investigation Platform

Phase 10 is the derived investigation layer over the Phase 8 Evidence Fabric and Phase 9 Security Lab.

## Scope

This phase provides:

- incident explorer views derived from trace/evidence data
- bounded provenance graph traversal
- chronological timeline reconstruction
- deterministic causal candidate scoring
- forensic replay reconstruction
- tenant-scoped evidence search
- explainability from redacted evidence metadata
- a TypeScript API client for dashboard integration

## Architectural rule

Phase 10 does not create authority and does not execute recovered actions.

Replay is deliberately represented as:

`executable = false`

The investigation layer distinguishes:

`identity != authority != influence != evidence`

## Persistence

Phase 10 adds no new database tables and no Alembic migration.

Investigation state is currently a derived read model over:

- `EvidenceNode`
- `EvidenceEdge`
- `SecurityEvent`

Case-management persistence can be introduced later in Phase 11 without rewriting the Phase 10 evidence/query contracts.

## Security boundaries

All API operations require a tenant context and owner/admin role.

All graph/search operations are bounded before database traversal.

Only redacted evidence metadata is exposed.

Raw evaluator reasoning is never returned by Phase 10.

Search operates on traceable evidence only.

## Router integration

The AURAGENT Phase 0–15 composition root is already designed to discover:

`app.api.investigation`

No rewrite of `main.py` is required by this phase.

## Deferred verification

Per project policy, this installer does not run the full test suite, frontend build, or final E2E verification.

Those belong to the final AURAGENT 0–15 verification pass.
