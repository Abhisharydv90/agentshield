# AURAGENT — Phase 13 Scale

Phase 13 establishes the distributed scale contracts required for a
multi-worker, multi-region AURAGENT deployment.

## Scope

- stateless-facing service boundaries
- deterministic sharding
- fenced worker leases
- distributed work queues
- event ordering
- request idempotency
- durable workflow checkpoint contracts
- region selection
- degradation/health evaluation

## Architectural rule

Scale changes where work is coordinated, not who has authority.

The scheduler never creates or increases agent authority.

Worker assignment therefore remains:

`work assignment != authority grant`

The Phase 4 Trust Kernel is still the authority boundary.

## Leases

Every worker lease has a monotonically increasing fencing token.

A stale worker must be rejected before it can act on a partition.

The included in-memory coordinator is a deterministic reference backend.
Production multi-worker deployments require a shared durable/linearizable
store.

## Events

The reference event bus models:

`tenant + topic + partition + contiguous sequence`

It does not claim exactly-once delivery. Consumers should assume
at-least-once delivery and combine it with the idempotency contract.

## Idempotency

The idempotency store binds:

`namespace + key + request_digest`

Reusing the same key with a different request digest is rejected.

## Workflow durability

Workflow checkpoints use optimistic versions so concurrent writers cannot
silently overwrite one another.

Phase 2 remains the runtime/workflow owner; Phase 13 provides the distributed
storage/coordination contract needed by scaled deployments.

## Sharding

Tenant sharding uses deterministic SHA-256-derived buckets. The algorithm is
vendor-neutral and stable for the same shard count.

Changing the shard count is a topology change and must be handled explicitly;
it is not silently remapped.

## Multi-region

Exactly one control-plane region is required by the reference contract.
Active workload regions can be selected by explicit preference or priority.

Invalid region configurations fail closed.

## Health

Health evaluation distinguishes healthy, degraded and unavailable states based
on bounded queue depth and event lag.

The health surface does not itself authorize failover actions.

## Persistence

Phase 13 adds no database migration. Durable production adapters should bind to
the existing runtime/control-plane stores instead of creating a parallel
authority database.

## Router integration

The AURAGENT composition root already discovers:

`app.api.scale`

No rewrite of `main.py` is required.

## Verification policy

The installer does not run the complete backend/frontend/E2E suite.

The agreed project process remains:

`implement Phases 0–15 → comprehensive final verification → commit/push`
