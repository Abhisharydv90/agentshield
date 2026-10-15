# AURAGENT — Phase 15 Research / Invention

Phase 15 is the final research layer in the AURAGENT 0–15 architecture.

## Research hypothesis

The central hypothesis is:

`Authority-Carrying Agents (ACA)`

with the invariant:

`A_child <= A_parent unless explicitly authorized`

The implementation is a research/reference layer. It is not a claim of
scientific novelty, patentability, or absence of prior art.

## Four-way separation

The model preserves:

`identity != authority`

`authority != influence`

`influence != evidence`

`memory != authority`

This is intended to stop information, external instructions, or stored memory
from accidentally becoming permission.

## Authority Conservation Engine

Authority is represented as a structured vector containing:

- capabilities
- operations
- resources
- data scopes
- network scopes
- delegation depth
- risk ceiling

A child transition is conserved only when it is no greater than its parent in
all authority-bearing dimensions.

The Phase 4 Trust Kernel remains the production authority owner.

## Provenance-conditioned authorization

The research primitive can require:

- minimum provenance trust grade
- required source identifiers
- integrity
- tenant matching
- bounded evidence age

This condition is evaluated separately from authority creation.

## Trusted memory

The Phase 6 Memory Fabric remains the durable memory owner.

Phase 15 combines memory integrity, provenance, poisoning signals and tenant
binding into a trust assessment.

A trusted memory result explicitly carries:

`authority_effect = none`

## Formal policy verification

The bounded verifier enumerates a finite model space across:

- capabilities
- operations
- provenance grades
- risk thresholds
- human approval state
- delegation depth

Correctly denied high-risk states are treated as successful enforcement, not
verification failures.

The result includes a deterministic verification hash.

This is a transparent bounded checker, not a universal theorem prover.

## Decision proofs

Research decision proofs bind:

- tenant
- trace
- subject
- policy hash
- authority-before hash
- authority-after hash
- provenance hash
- decision
- reason
- containment mode

The proof is explicitly:

`executable = false`

The proof is evidence, not an authority token.

## Autonomous containment

The research layer can construct a containment plan containing:

- observe
- quarantine
- revoke delegation
- disable tool
- isolate workload
- require human review

The plan is always:

`autonomous_execution_allowed = false`

The research layer does not execute shell commands, kill processes, modify
production credentials, or directly mutate runtime tools.

A later production adapter can require Phase 4 authorization, Phase 7 isolation,
and the appropriate human approval before executing an approved plan.

## API

The API is tenant scoped and owner/admin only.

It exposes:

- research evaluation
- bounded formal policy verification
- invariant inspection

No authority-grant API is provided.

## Persistence

Phase 15 adds no database migration. Research artifacts can later be persisted
through Phase 8 Evidence Fabric or another dedicated research store.

## Router

The existing AURAGENT composition root is designed to discover:

`app.api.research`

No rewrite of `main.py` is required.

## AURAGENT 0–15 completion

After applying this phase, the planned implementation layers are present:

`0 Foundation`
`0.5 Hardening`
`1 Development Platform`
`2 Runtime & Orchestration`
`3 Gateway`
`4 Trust & Security Kernel`
`5 Tool Fabric`
`6 Memory Fabric`
`7 Isolation Fabric`
`8 Evidence Fabric`
`9 Security Lab`
`10 Investigation Platform`
`11 Control Plane`
`12 Ecosystem`
`13 Scale`
`14 Enterprise`
`15 Research / Invention`

The next step is one comprehensive AURAGENT 0–15 verification pass.
