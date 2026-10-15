"""Phase 4 pure trust-kernel tests.

These are intentionally separate from the existing database/integration
suite. They can run without Postgres or Redis after the AURAGENT dependency
set is installed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.security.delegation.conservation import AuthorityConservationEngine
from app.security.delegation.model import AuthorityState
from app.security.identity.crypto import AgentIdentityDocument, IdentityKeyPair
from app.security.proofs.authority_token import AuthorityToken
from app.security.proofs.decision_proof import DecisionProof
from app.security.proofs.policy_commitment import PolicyCommitment


def test_identity_signature_and_fingerprint() -> None:
    pair = IdentityKeyPair.generate()
    payload = {"agent": str(uuid.uuid4()), "purpose": "phase4"}
    signature = pair.sign(payload)
    assert pair.verify(payload, signature)
    assert not pair.verify({**payload, "purpose": "tampered"}, signature)
    assert len(pair.fingerprint) == 64


def test_authority_conservation_denies_escalation() -> None:
    parent = AuthorityState.from_values(
        capabilities={"agent:invoke", "tool:read"},
        operations={"read"},
        delegation_depth=2,
        risk_ceiling=60,
    )
    child = AuthorityState.from_values(
        capabilities={"agent:invoke", "tool:write"},
        operations={"read"},
        delegation_depth=2,
        risk_ceiling=70,
    )
    result = AuthorityConservationEngine().compare(parent, child)
    assert not result.allowed
    assert any(v.field == "capabilities" for v in result.violations)
    assert any(v.field == "risk_ceiling" for v in result.violations)


def test_authority_token_binds_subject_and_policy() -> None:
    pair = IdentityKeyPair.generate()
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    authority = AuthorityState.from_values(capabilities={"agent:invoke"})
    token = AuthorityToken.issue(
        signer=pair,
        tenant_id=tenant_id,
        issuer_agent_id=agent_id,
        subject_agent_id=agent_id,
        authority=authority,
        policy_hash="a" * 64,
        ttl_seconds=300,
    )
    assert token.verify(pair.public_key_b64, expected_tenant_id=tenant_id, expected_subject_agent_id=agent_id)
    assert not token.verify(pair.public_key_b64, expected_tenant_id=uuid.uuid4(), expected_subject_agent_id=agent_id)


def test_policy_commitment_changes_when_content_changes() -> None:
    first = PolicyCommitment.from_policy({"name": "p", "version": "1", "rules": {"read": "allow"}})
    second = PolicyCommitment.from_policy({"name": "p", "version": "1", "rules": {"read": "deny"}})
    assert first.content_hash != second.content_hash


def test_decision_proof_changes_when_action_changes() -> None:
    pair = IdentityKeyPair.generate()
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    kwargs = dict(
        signer=pair,
        tenant_id=tenant_id,
        agent_id=agent_id,
        trace_id="trace",
        decision="allow",
        reason="authorized",
        policy_hash="b" * 64,
        capability_snapshot=["agent:invoke"],
        authority_token_hash="c" * 64,
    )
    first = DecisionProof.create(action={"op": "invoke", "model": "x"}, **kwargs)
    second = DecisionProof.create(action={"op": "invoke", "model": "y"}, **kwargs)
    assert first.action_hash != second.action_hash
    assert first.proof_hash != second.proof_hash
    assert first.verify(pair.public_key_b64)
