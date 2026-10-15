# AURAGENT Phase 6 — Memory Fabric

Phase 6 implements the durable memory boundary described by the AURAGENT roadmap.

## Design rule

Memory is **influence**, not authority.

A retrieved memory may be included in an agent's reasoning context, but memory
content cannot create or increase:

- capabilities
- delegated authority
- approvals
- policy permissions
- network scope
- tool permissions
- isolation privileges

## Implemented

- tenant-scoped durable memory
- user / agent / tool / external / summary / system memory types
- SHA-256 content commitments
- source metadata + source content verification
- immutable version history with chained hashes
- optimistic concurrency control
- retention policy
- deterministic semantic retrieval baseline
- integrity-first retrieval
- poisoning heuristics
- reject/quarantine behavior
- tamper-evident lineage records
- API boundary through authenticated agent SecurityContext

## Semantic provider strategy

The current baseline is deterministic and vendor-neutral. A production vector
backend can be introduced later without changing the MemoryStore public
contract.

## Security rationale

OWASP's current agentic-security guidance treats persistent memory/context as
an attack surface, including memory poisoning and cross-session influence.
AURAGENT therefore verifies stored content before it becomes retrieval context
and preserves provenance/influence metadata separately from authority.
