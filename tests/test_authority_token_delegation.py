"""P0 regression coverage for authority-token delegation and conservation."""

from __future__ import annotations

import uuid

import pytest

from app.db.models import Agent, AgentIdentity
from app.policy.dsl import Policy
from app.security.delegation.model import AuthorityState
from app.security.identity.crypto import IdentityKeyPair
from app.security.kernel import AuthorityDeniedError, SecurityKernel
from app.security.proofs.authority_token import AuthorityToken
from app.security.proofs.policy_commitment import PolicyCommitment


def _agent(tenant_id, agent_id, scopes):
    return Agent(
        agent_id=agent_id,
        tenant_id=tenant_id,
        name=str(agent_id),
        scopes=scopes,
        status="active",
    )


def _identity(tenant_id, agent_id, pair):
    return AgentIdentity(
        identity_id=uuid.uuid4(),
        tenant_id=tenant_id,
        agent_id=agent_id,
        key_id=pair.fingerprint,
        algorithm="Ed25519",
        public_key=pair.public_key_b64,
        fingerprint=pair.fingerprint,
        status="active",
    )


def _policy_hash():
    return PolicyCommitment.from_policy(
        Policy(name="delegation-test", version="1", rules=[])
    ).content_hash


def test_delegated_token_requires_parent_and_different_subject():
    tenant = uuid.uuid4()
    parent = uuid.uuid4()
    child = uuid.uuid4()
    pair = IdentityKeyPair.generate()

    with pytest.raises(ValueError, match="parent_token_hash"):
        AuthorityToken.issue(
            signer=pair,
            tenant_id=tenant,
            issuer_agent_id=parent,
            subject_agent_id=child,
            authority=AuthorityState.from_values(capabilities={"agent:invoke"}),
            policy_hash="a" * 64,
            ttl_seconds=300,
        )

    with pytest.raises(ValueError, match="different subject"):
        AuthorityToken.issue(
            signer=pair,
            tenant_id=tenant,
            issuer_agent_id=parent,
            subject_agent_id=parent,
            authority=AuthorityState.from_values(capabilities={"agent:invoke"}),
            policy_hash="a" * 64,
            ttl_seconds=300,
            parent_token_hash="b" * 64,
        )


def test_valid_two_hop_chain_is_accepted():
    tenant = uuid.uuid4()
    parent_id = uuid.uuid4()
    child_id = uuid.uuid4()
    parent_pair = IdentityKeyPair.generate()

    parent_agent = _agent(
        tenant,
        parent_id,
        ["agent:delegate", "agent:invoke", "tool:read"],
    )
    child_agent = _agent(
        tenant,
        child_id,
        ["agent:invoke", "tool:read"],
    )
    policy_hash = _policy_hash()

    parent_authority = AuthorityState.from_values(
        capabilities={"agent:delegate", "agent:invoke", "tool:read"},
        operations={"read"},
        delegation_depth=2,
        risk_ceiling=80,
    )
    child_authority = AuthorityState.from_values(
        capabilities={"agent:invoke", "tool:read"},
        operations={"read"},
        delegation_depth=2,
        risk_ceiling=70,
    )

    root = AuthorityToken.issue(
        signer=parent_pair,
        tenant_id=tenant,
        issuer_agent_id=parent_id,
        subject_agent_id=parent_id,
        authority=parent_authority,
        policy_hash=policy_hash,
        ttl_seconds=300,
    )
    child = AuthorityToken.issue(
        signer=parent_pair,
        tenant_id=tenant,
        issuer_agent_id=parent_id,
        subject_agent_id=child_id,
        authority=child_authority,
        policy_hash=policy_hash,
        ttl_seconds=240,
        parent_token_hash=root.token_hash,
    )

    context = SecurityKernel().validate_authority_chain(
        token_chain=(root, child),
        target_agent=child_agent,
        issuer_identities={
            parent_id: _identity(tenant, parent_id, parent_pair),
        },
        issuer_agents={parent_id: parent_agent},
        expected_policy_hash=policy_hash,
        trace_id="delegation-trace",
    )

    assert context.agent_id == child_id
    assert context.authority == child_authority
    assert context.authority_token_hash == child.token_hash


def test_delegated_token_cannot_escalate_parent_authority():
    tenant = uuid.uuid4()
    parent_id = uuid.uuid4()
    child_id = uuid.uuid4()
    pair = IdentityKeyPair.generate()

    parent_agent = _agent(
        tenant,
        parent_id,
        ["agent:delegate", "agent:invoke", "tool:read"],
    )
    child_agent = _agent(
        tenant,
        child_id,
        ["agent:invoke", "tool:read"],
    )
    policy_hash = _policy_hash()

    parent_authority = AuthorityState.from_values(
        capabilities={"agent:delegate", "agent:invoke", "tool:read"},
        operations={"read"},
        delegation_depth=1,
        risk_ceiling=50,
    )
    root = AuthorityToken.issue(
        signer=pair,
        tenant_id=tenant,
        issuer_agent_id=parent_id,
        subject_agent_id=parent_id,
        authority=parent_authority,
        policy_hash=policy_hash,
        ttl_seconds=300,
    )
    escalated = AuthorityToken.issue(
        signer=pair,
        tenant_id=tenant,
        issuer_agent_id=parent_id,
        subject_agent_id=child_id,
        authority=AuthorityState.from_values(
            capabilities={"agent:delegate", "agent:invoke", "tool:read"},
            operations={"read"},
            delegation_depth=1,
            risk_ceiling=90,
        ),
        policy_hash=policy_hash,
        ttl_seconds=240,
        parent_token_hash=root.token_hash,
    )

    with pytest.raises(AuthorityDeniedError, match="exceeds_parent_authority"):
        SecurityKernel().validate_authority_chain(
            token_chain=(root, escalated),
            target_agent=child_agent,
            issuer_identities={parent_id: _identity(tenant, parent_id, pair)},
            issuer_agents={parent_id: parent_agent},
            expected_policy_hash=policy_hash,
            trace_id="trace",
        )


def test_delegated_token_signed_by_unrelated_agent_is_rejected():
    tenant = uuid.uuid4()
    parent_id = uuid.uuid4()
    child_id = uuid.uuid4()
    unrelated_id = uuid.uuid4()
    parent_pair = IdentityKeyPair.generate()
    unrelated_pair = IdentityKeyPair.generate()

    parent_agent = _agent(
        tenant,
        parent_id,
        ["agent:delegate", "agent:invoke", "tool:read"],
    )
    child_agent = _agent(
        tenant,
        child_id,
        ["agent:invoke", "tool:read"],
    )
    policy_hash = _policy_hash()

    root = AuthorityToken.issue(
        signer=parent_pair,
        tenant_id=tenant,
        issuer_agent_id=parent_id,
        subject_agent_id=parent_id,
        authority=AuthorityState.from_values(
            capabilities={"agent:delegate", "agent:invoke", "tool:read"},
            operations={"read"},
        ),
        policy_hash=policy_hash,
        ttl_seconds=300,
    )
    child = AuthorityToken.issue(
        signer=unrelated_pair,
        tenant_id=tenant,
        issuer_agent_id=unrelated_id,
        subject_agent_id=child_id,
        authority=AuthorityState.from_values(
            capabilities={"agent:invoke"},
            operations={"read"},
        ),
        policy_hash=policy_hash,
        ttl_seconds=240,
        parent_token_hash=root.token_hash,
    )

    with pytest.raises(
        AuthorityDeniedError,
        match="issuer_not_found|issuer_identity",
    ):
        SecurityKernel().validate_authority_chain(
            token_chain=(root, child),
            target_agent=child_agent,
            issuer_identities={
                parent_id: _identity(tenant, parent_id, parent_pair),
            },
            issuer_agents={parent_id: parent_agent},
            expected_policy_hash=policy_hash,
            trace_id="trace",
        )


def test_single_self_issued_token_still_works():
    tenant = uuid.uuid4()
    agent_id = uuid.uuid4()
    pair = IdentityKeyPair.generate()
    agent = _agent(
        tenant,
        agent_id,
        ["agent:invoke", "tool:read"],
    )
    identity = _identity(tenant, agent_id, pair)
    policy_hash = _policy_hash()

    token = AuthorityToken.issue(
        signer=pair,
        tenant_id=tenant,
        issuer_agent_id=agent_id,
        subject_agent_id=agent_id,
        authority=AuthorityState.from_values(
            capabilities={"agent:invoke", "tool:read"},
        ),
        policy_hash=policy_hash,
        ttl_seconds=300,
    )

    context = SecurityKernel().validate_token_against_agent(
        token=token,
        identity=identity,
        agent=agent,
        expected_policy_hash=policy_hash,
        trace_id="trace",
    )

    assert context.agent_id == agent_id


def test_delegated_capability_ceiling_is_part_of_action_identity():
    from app.security.decision.contract import SecurityAction

    tenant = uuid.uuid4()
    agent = uuid.uuid4()

    action = SecurityAction(
        tenant_id=tenant,
        agent_id=agent,
        trace_id="trace",
        tool_name="email.send",
        operation="external_call",
        target="example.com",
        arguments={"to": "user@example.com"},
        capabilities=["tool:execute"],
        policy_version="1",
        policy_hash="a" * 64,
        capability_snapshot_hash="b" * 64,
        effective_capabilities=["tool:execute"],
        authority_token_hash="c" * 64,
    )

    payload = action.to_dict()
    assert payload["effective_capabilities"] == ["tool:execute"]
    assert payload["authority_token_hash"] == "c" * 64


def test_authority_token_chain_rejects_parent_hash_mismatch():
    tenant = uuid.uuid4()
    parent_id = uuid.uuid4()
    child_id = uuid.uuid4()
    pair = IdentityKeyPair.generate()
    policy_hash = _policy_hash()

    parent_agent = _agent(
        tenant,
        parent_id,
        ["agent:delegate", "agent:invoke", "tool:read"],
    )
    child_agent = _agent(
        tenant,
        child_id,
        ["agent:invoke", "tool:read"],
    )

    root = AuthorityToken.issue(
        signer=pair,
        tenant_id=tenant,
        issuer_agent_id=parent_id,
        subject_agent_id=parent_id,
        authority=AuthorityState.from_values(
            capabilities={"agent:delegate", "agent:invoke", "tool:read"},
            operations={"read"},
        ),
        policy_hash=policy_hash,
        ttl_seconds=300,
    )
    child = AuthorityToken.issue(
        signer=pair,
        tenant_id=tenant,
        issuer_agent_id=parent_id,
        subject_agent_id=child_id,
        authority=AuthorityState.from_values(
            capabilities={"agent:invoke", "tool:read"},
            operations={"read"},
        ),
        policy_hash=policy_hash,
        ttl_seconds=240,
        parent_token_hash="d" * 64,
    )

    with pytest.raises(AuthorityDeniedError, match="signature_or_chain_invalid"):
        SecurityKernel().validate_authority_chain(
            token_chain=(root, child),
            target_agent=child_agent,
            issuer_identities={
                parent_id: _identity(tenant, parent_id, pair),
            },
            issuer_agents={parent_id: parent_agent},
            expected_policy_hash=policy_hash,
            trace_id="trace",
        )
