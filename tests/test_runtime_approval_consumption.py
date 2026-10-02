"""Runtime approval consumption tests for Batch 7E."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.config import settings
from app.db.models import Agent, ApprovalRequest, Tenant, User
from app.db.session import async_session
from app.policy.dsl import Policy, ToolRule
from app.security.decision.contract import ApprovalState
from app.security.decision.engine import SecurityDecisionEngine
from app.security.judge.evaluate import execute_tool_with_judge
from app.security.passwords import hash_password


pytestmark = pytest.mark.asyncio


def _step_up_policy() -> Policy:
    return Policy(
        name="runtime-approval-test",
        version="approval-policy-1",
        default="deny",
        rules=[
            ToolRule(
                tool_pattern="db.execute",
                op="write",
                target_allowlist=["billing_invoices"],
                decision="step_up",
            ),
            ToolRule(
                tool_pattern="*",
                decision="deny",
            ),
        ],
    )


def _raw_write_call(command: str = "INSERT INTO billing_invoices VALUES (1)") -> dict:
    return {
        "name": "db.execute",
        "args": {
            "query": command,
            "table": "billing_invoices",
        },
    }


async def _create_context():
    async with async_session() as session:
        tenant = Tenant(
            slug=f"runtime-approval-{uuid.uuid4().hex[:10]}",
            name="Runtime Approval Test Tenant",
            status="active",
        )
        session.add(tenant)
        await session.flush()

        user = User(
            tenant_id=tenant.tenant_id,
            email=f"runtime-{uuid.uuid4().hex[:10]}@example.test",
            password_hash=hash_password("TestPass123"),
            name="Runtime Approval User",
            role="owner",
            status="active",
            session_version=0,
        )
        session.add(user)
        await session.flush()

        agent = Agent(
            tenant_id=tenant.tenant_id,
            name="runtime-approval-agent",
            scopes=[
                "agent:invoke",
                "tool:write",
            ],
            status="active",
        )
        session.add(agent)
        await session.flush()

        await session.commit()

    return tenant, user, agent


async def _cleanup(tenant_id: uuid.UUID) -> None:
    async with async_session() as session:
        await session.execute(
            Tenant.__table__.delete().where(
                Tenant.tenant_id == tenant_id
            )
        )
        await session.commit()


async def _create_pending_approval(
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
) -> str:
    policy = _step_up_policy()

    result = await execute_tool_with_judge(
        raw_tool_call=_raw_write_call(),
        policy=policy,
        policy_version=policy.version,
        tenant_id=tenant_id,
        trace_id=f"initial-{uuid.uuid4().hex}",
        agent_scopes=[
            "agent:invoke",
            "tool:write",
        ],
        agent_id=agent_id,
    )

    assert result["decision"] == "approval_required"
    assert result["approval_id"]
    assert result["action_fingerprint"]

    return result["approval_id"]


async def _approve(
    approval_id: str,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
) -> None:
    async with async_session() as session:
        approval = await SecurityDecisionEngine(
            session
        ).decide(
            approval_id=uuid.UUID(approval_id),
            tenant_id=tenant_id,
            approver_user_id=user_id,
            approve=True,
            reason="approved for runtime consumption test",
        )
        assert approval.state == ApprovalState.APPROVED.value
        await session.commit()


@pytest.fixture(autouse=True)
def _judge_disabled(monkeypatch):
    monkeypatch.setattr(settings, "KILL_JUDGE", True)
    monkeypatch.setattr(settings, "JUDGE_ENFORCE", False)


async def test_approved_action_is_consumed_once_with_fresh_trace():
    tenant, user, agent = await _create_context()
    try:
        approval_id = await _create_pending_approval(
            tenant.tenant_id,
            agent.agent_id,
        )
        await _approve(
            approval_id,
            tenant.tenant_id,
            user.user_id,
        )

        result = await execute_tool_with_judge(
            raw_tool_call=_raw_write_call(),
            policy=_step_up_policy(),
            policy_version="approval-policy-1",
            tenant_id=tenant.tenant_id,
            trace_id=f"retry-{uuid.uuid4().hex}",
            agent_scopes=[
                "agent:invoke",
                "tool:write",
            ],
            agent_id=agent.agent_id,
            approval_id=approval_id,
        )

        assert result["decision"] == "allow"
        assert result["approval_id"] == approval_id
        assert result["action_fingerprint"]

        async with async_session() as session:
            approval = await session.get(
                ApprovalRequest,
                uuid.UUID(approval_id),
            )
            assert approval is not None
            assert approval.state == ApprovalState.CONSUMED.value
    finally:
        await _cleanup(tenant.tenant_id)


async def test_same_approval_cannot_be_replayed():
    tenant, user, agent = await _create_context()
    try:
        approval_id = await _create_pending_approval(
            tenant.tenant_id,
            agent.agent_id,
        )
        await _approve(
            approval_id,
            tenant.tenant_id,
            user.user_id,
        )

        first = await execute_tool_with_judge(
            raw_tool_call=_raw_write_call(),
            policy=_step_up_policy(),
            policy_version="approval-policy-1",
            tenant_id=tenant.tenant_id,
            trace_id="replay-first",
            agent_scopes=[
                "agent:invoke",
                "tool:write",
            ],
            agent_id=agent.agent_id,
            approval_id=approval_id,
        )
        assert first["decision"] == "allow"

        second = await execute_tool_with_judge(
            raw_tool_call=_raw_write_call(),
            policy=_step_up_policy(),
            policy_version="approval-policy-1",
            tenant_id=tenant.tenant_id,
            trace_id="replay-second",
            agent_scopes=[
                "agent:invoke",
                "tool:write",
            ],
            agent_id=agent.agent_id,
            approval_id=approval_id,
        )

        assert second["decision"] == "deny"
        assert second["reason"] == (
            "approval_consumption_failed:approval_not_consumable:consumed"
        )
    finally:
        await _cleanup(tenant.tenant_id)


async def test_changed_arguments_do_not_match_approved_action():
    tenant, user, agent = await _create_context()
    try:
        approval_id = await _create_pending_approval(
            tenant.tenant_id,
            agent.agent_id,
        )
        await _approve(
            approval_id,
            tenant.tenant_id,
            user.user_id,
        )

        changed = await execute_tool_with_judge(
            raw_tool_call=_raw_write_call(
                "INSERT INTO billing_invoices VALUES (999)"
            ),
            policy=_step_up_policy(),
            policy_version="approval-policy-1",
            tenant_id=tenant.tenant_id,
            trace_id="changed-args",
            agent_scopes=[
                "agent:invoke",
                "tool:write",
            ],
            agent_id=agent.agent_id,
            approval_id=approval_id,
        )

        assert changed["decision"] == "deny"
        assert changed["reason"] == (
            "approval_consumption_failed:approval_action_mismatch"
        )

        async with async_session() as session:
            approval = await session.get(
                ApprovalRequest,
                uuid.UUID(approval_id),
            )
            assert approval is not None
            assert approval.state == ApprovalState.APPROVED.value
    finally:
        await _cleanup(tenant.tenant_id)


async def test_wrong_approval_id_cannot_authorize_action():
    tenant, user, agent = await _create_context()
    try:
        approval_id = await _create_pending_approval(
            tenant.tenant_id,
            agent.agent_id,
        )
        await _approve(
            approval_id,
            tenant.tenant_id,
            user.user_id,
        )

        other_id = str(uuid.uuid4())

        result = await execute_tool_with_judge(
            raw_tool_call=_raw_write_call(),
            policy=_step_up_policy(),
            policy_version="approval-policy-1",
            tenant_id=tenant.tenant_id,
            trace_id="wrong-approval",
            agent_scopes=[
                "agent:invoke",
                "tool:write",
            ],
            agent_id=agent.agent_id,
            approval_id=other_id,
        )

        assert result["decision"] == "deny"
        assert result["reason"] == "approval_not_found"
    finally:
        await _cleanup(tenant.tenant_id)


async def test_revoked_capability_blocks_consumption():
    tenant, user, agent = await _create_context()
    try:
        approval_id = await _create_pending_approval(
            tenant.tenant_id,
            agent.agent_id,
        )
        await _approve(
            approval_id,
            tenant.tenant_id,
            user.user_id,
        )

        async with async_session() as session:
            db_agent = await session.get(
                Agent,
                agent.agent_id,
            )
            assert db_agent is not None
            db_agent.scopes = ["agent:invoke"]
            await session.commit()

        result = await execute_tool_with_judge(
            raw_tool_call=_raw_write_call(),
            policy=_step_up_policy(),
            policy_version="approval-policy-1",
            tenant_id=tenant.tenant_id,
            trace_id="capability-revoked",
            agent_scopes=["agent:invoke"],
            agent_id=agent.agent_id,
            approval_id=approval_id,
        )

        assert result["decision"] == "deny"
        assert result["reason"].startswith(
            "missing_capabilities:"
        )

        async with async_session() as session:
            approval = await session.get(
                ApprovalRequest,
                uuid.UUID(approval_id),
            )
            assert approval is not None
            assert approval.state == ApprovalState.APPROVED.value
    finally:
        await _cleanup(tenant.tenant_id)
