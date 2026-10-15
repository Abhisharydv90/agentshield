# AURAGENT Phase 8 — Evidence Fabric completion

The master AURAGENT roadmap defines Evidence Fabric as:

- traces
- provenance graph
- immutable audit
- replay
- causal linkage
- verification
- compliance exports

The repository already contains the Phase 7F evidence foundation and forensic
investigation capabilities. Phase 8 adds the remaining distributed-scale and
compliance-facing completion surfaces:

- distributed evidence invariants
- fenced writer lease contract
- explicit external anchoring contract
- human/admin evidence controls
- deterministic compliance-package hashes
- dashboard client for evidence administration
- local scale/integrity regression tests

## Replay rule

Replay is strictly forensic reconstruction. It does not execute tools, invoke
agents, mutate runtime state, or recreate side effects.

## External anchoring rule

Anchoring is opt-in. The provider sends a cryptographic package commitment,
not the raw evidence package. It is never launched automatically by application
startup.

## Existing foundation

Phase 7F already supplies the tenant-scoped Evidence Graph, cryptographic
fingerprints, runtime evidence creation, query/graph traversal and bounded
forensic reconstruction. This Phase 8 package does not rewrite those foundation
modules.
