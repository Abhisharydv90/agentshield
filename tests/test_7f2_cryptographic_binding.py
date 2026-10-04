"""7F-2 cryptographic runtime-binding tests."""

from __future__ import annotations

import uuid

import pytest

from app.config import settings
from app.db.models import Agent, ApprovalRequest, Tenant, User
from app.db.session import async_session
from app.policy.dsl import Policy, ToolRule
from app.security.decision.contract import ApprovalState
from app.security.evidence.binding import (
    approval_decision_hash,
    capability_snapshot_hash,
    policy_snapshot_hash,
)
from app.security.judge.evaluate import execute_tool_with_judge
from app.security.passwords import hash_password


def _policy() -> Policy:
    return Policy(
        name="binding-test-policy",
        version="1.0.0",
        default="deny",
        rules=[
            ToolRule(
                tool_pattern="db.execute",
                op="write",
                target_allowlist=["billing_invoices"],
                decision="step_up",
            ),
            ToolRule(tool_pattern="*", decision="deny"),
        ],
    )


def _changed_policy() -> Policy:
    return Policy(
        name="binding-test-policy",
        version="1.0.0",
        default="deny",
        rules=[
            ToolRule(
                tool_pattern="db.execute",
                op="write",
                target_allowlist=["billing_invoices"],
                max_rows=2,
                decision="step_up",
            ),
            ToolRule(tool_pattern="*", decision="deny"),
        ],
    )


def _call() -> dict:
    return {
        "name": "db.execute",
        "args": {
            "query": "INSERT INTO billing_invoices VALUES (1)",
            "table": "billing_invoices",
        },
    }


def test_policy_hash_changes_when_content_changes():
    assert policy_snapshot_hash(_policy()) != policy_snapshot_hash(_changed_policy())


def test_capability_hash_changes_when_scope_changes():
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    first = capability_snapshot_hash(
        tenant_id=tenant_id,
        agent_id=agent_id,
        status="active",
        scopes=["agent:invoke", "tool:write"],
    )
    changed = capability_snapshot_hash(
        tenant_id=tenant_id,
        agent_id=agent_id,
        status="active",
        scopes=["agent:invoke"],
    )
    assert first != changed


def test_approval_decision_hash_changes_when_policy_changes():
    args = {
        "action_fingerprint": "a" * 64,
        "policy_hash": "b" * 64,
        "capability_snapshot_hash": "c" * 64,
    }
    assert approval_decision_hash(**args) != approval_decision_hash(
        **{**args, "policy_hash": "d" * 64}
    )


async def _context():
    async with async_session() as session:
        tenant = Tenant(
            slug=f"binding-{uuid.uuid4().hex[:12]}",
            name="7F-2 Binding",
            status="active",
        )
        session.add(tenant)
        await session.flush()

        user = User(
            tenant_id=tenant.tenant_id,
            email=f"binding-{uuid.uuid4().hex[:12]}@example.test",
            password_hash=hash_password("TestPass123"),
            name="Binding User",
            role="owner",
            status="active",
        )
        agent = Agent(
            tenant_id=tenant.tenant_id,
            name="binding-agent",
            scopes=["agent:invoke", "tool:write"],
            status="active",
        )
        session.add_all([user, agent])
        await session.commit()
    return tenant, user, agent


async def _cleanup(tenant_id: uuid.UUID):
    async with async_session() as session:
        await session.execute(
            Tenant.__table__.delete().where(Tenant.tenant_id == tenant_id)
        )
        await session.commit()


async def test_runtime_approval_contains_cryptographic_bindings():
    tenant, user, agent = await _context()
    try:
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(settings, "KILL_JUDGE", True)
        monkeypatch.setattr(settings, "JUDGE_ENFORCE", False)
        try:
            result = await execute_tool_with_judge(
                raw_tool_call=_call(),
                policy=_policy(),
                policy_version="1.0.0",
                tenant_id=tenant.tenant_id,
                trace_id="binding-trace",
                agent_scopes=["agent:invoke", "tool:write"],
                agent_id=agent.agent_id,
            )
        finally:
            monkeypatch.undo()

        assert result["decision"] == "approval_required"
        assert len(result["policy_hash"]) == 64
        assert len(result["capability_snapshot_hash"]) == 64
        assert len(result["decision_hash"]) == 64

        async with async_session() as session:
            approval = await session.get(
                ApprovalRequest,
                uuid.UUID(result["approval_id"]),
            )
            assert approval is not None
            assert approval.state == ApprovalState.PENDING.value
            assert approval.policy_hash == result["policy_hash"]
            assert approval.capability_snapshot_hash == result["capability_snapshot_hash"]
            assert approval.decision_hash == result["decision_hash"]
    finally:
        await _cleanup(tenant.tenant_id)
