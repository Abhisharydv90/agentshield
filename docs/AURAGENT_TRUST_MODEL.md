# AURAGENT Master Trust Model

AURAGENT is the umbrella project:
**Autonomous Agent Infrastructure & Trust Fabric**

AgentShield is a component inside AURAGENT, primarily implementing trust/security
controls in AURAGENT Core and at enforcement boundaries.

## Trust dimensions

1. Identity — who is acting?
2. Authority — what may the actor do?
3. Influence — what information affected reasoning?
4. Evidence — what proves what happened?

Invariant:

**Identity != Authority != Influence != Evidence**

Untrusted content may influence reasoning without receiving authority.

## Authority state

A conceptual authority state is:

A = (T, O, R, D, N, time, budget, delegation_depth, risk_ceiling)

Delegation should conserve or attenuate authority:

A_child <= A_parent

unless an explicitly authorized escalation occurs.

## Proof-carrying action direction

A consequential action should eventually be bound to:

- identity
- delegated authority
- capability snapshot
- policy snapshot
- risk/decision state
- approval
- execution environment
- evidence root

AgentShield 7F-2 implements the first cryptographic runtime-binding slice:

- action_fingerprint
- policy_hash
- capability_snapshot_hash
- decision_hash

## Target provenance chain

REQUEST
-> AGENT
-> IDENTITY
-> CAPABILITY
-> MEMORY / EXTERNAL CONTENT
-> PLAN
-> POLICY
-> DELEGATION
-> TOOL
-> DECISION
-> APPROVAL
-> EXECUTION
-> RESULT
-> AUDIT
-> EVIDENCE

## Research hypothesis

Working name: **Authority-Carrying Agents (ACA)**

Supporting engine: **Authority Conservation Engine (ACE)**

This is a research hypothesis, not a novelty or patentability claim.

Potential differentiation to investigate:

- authority conservation through delegation
- influence/authority separation
- proof-carrying consequential actions
- provenance-conditioned authorization
- cryptographic evidence roots
- runtime enforcement before side effects
- automatic quarantine when authority invariants are violated

Prior-art and patent research remains mandatory.
