"""
Security Decision Engine tests.

These tests prove:

    - active agents with sufficient capabilities can be allowed
    - approval requests are persisted
    - approval is bound to the exact action fingerprint
    - expired approvals cannot be consumed
    - an approved action can only be consumed once
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.db.models import (
    Agent,
    Tenant,
    User,
)
from app.db.session import async_session
from app.security.decision.contract import (
    ApprovalState,
    SecurityAction,
    SecurityDecision,
)
from app.security.decision.engine import (
    SecurityDecisionEngine,
)


@pytest.fixture
async def decision_fixture():

    tenant_id: uuid.UUID

    user_id: uuid.UUID

    agent_id: uuid.UUID

    async with async_session() as session:

        tenant = Tenant(
            slug=(
                "decision-engine-"
                f"{uuid.uuid4().hex[:10]}"
            ),
            name="Decision Engine Test",
        )

        session.add(
            tenant
        )

        await session.flush()

        user = User(
            tenant_id=tenant.tenant_id,
            email=(
                "decision-"
                f"{uuid.uuid4().hex}@example.com"
            ),
            password_hash="test",
            name="Approval User",
            role="owner",
            email_verified=True,
            status="active",
        )

        agent = Agent(
            tenant_id=tenant.tenant_id,
            name="Decision Agent",
            description="Decision engine test agent",
            scopes=[
                "agent:invoke",
                "tool:read",
                "tool:write",
                "tool:execute",
                "network:egress",
            ],
            status="active",
        )

        session.add_all(
            [
                user,
                agent,
            ]
        )

        await session.commit()

        tenant_id = tenant.tenant_id
        user_id = user.user_id
        agent_id = agent.agent_id

    yield {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "agent_id": agent_id,
    }

    async with async_session() as session:

        tenant = await session.get(
            Tenant,
            tenant_id,
        )

        if tenant is not None:
            await session.delete(
                tenant
            )

        await session.commit()


def _action(
    fixture,
) -> SecurityAction:

    return SecurityAction(
        tenant_id=fixture["tenant_id"],
        agent_id=fixture["agent_id"],
        trace_id="decision-test-trace",
        tool_name="db.query",
        operation="read",
        target="billing_invoices",
        arguments={
            "query": (
                "SELECT * FROM billing_invoices"
            ),
        },
        capabilities=[
            "tool:read",
        ],
        policy_version="1.0.0",
        provenance={
            "source": "test",
        },
    )


@pytest.mark.asyncio
async def test_allow_active_agent_with_capability(
    decision_fixture,
):

    async with async_session() as session:

        engine = SecurityDecisionEngine(
            session
        )

        result = await engine.authorize(
            _action(decision_fixture)
        )

        assert result.decision == (
            SecurityDecision.ALLOW
        )

        assert result.approval_id is None


@pytest.mark.asyncio
async def test_approval_request_is_persisted(
    decision_fixture,
):

    async with async_session() as session:

        engine = SecurityDecisionEngine(
            session
        )

        result = await engine.authorize(
            _action(decision_fixture),
            require_human_approval=True,
        )

        assert result.decision == (
            SecurityDecision.APPROVAL_REQUIRED
        )

        assert result.approval_id is not None

        await session.commit()

        approval = await engine.get_approval(
            result.approval_id,
            decision_fixture["tenant_id"],
        )

        assert approval is not None

        assert approval.state == (
            ApprovalState.PENDING.value
        )

        assert approval.action_fingerprint == (
            result.action_fingerprint
        )


@pytest.mark.asyncio
async def test_approval_is_bound_to_action(
    decision_fixture,
):

    async with async_session() as session:

        engine = SecurityDecisionEngine(
            session
        )

        original = _action(
            decision_fixture
        )

        result = await engine.authorize(
            original,
            require_human_approval=True,
        )

        assert result.approval_id is not None

        await session.commit()

        await engine.decide(
            approval_id=result.approval_id,
            tenant_id=decision_fixture["tenant_id"],
            approver_user_id=decision_fixture["user_id"],
            approve=True,
            reason="approved for test",
        )

        await session.commit()

        altered = SecurityAction(
            tenant_id=original.tenant_id,
            agent_id=original.agent_id,
            trace_id=original.trace_id,
            tool_name=original.tool_name,
            operation=original.operation,
            target="different_table",
            arguments=original.arguments,
            capabilities=original.capabilities,
            policy_version=original.policy_version,
            provenance=original.provenance,
        )

        with pytest.raises(
            ValueError,
            match="approval_action_mismatch",
        ):

            await engine.consume(
                approval_id=result.approval_id,
                tenant_id=decision_fixture["tenant_id"],
                expected_action_fingerprint=(
                    altered.fingerprint()
                ),
            )


@pytest.mark.asyncio
async def test_approved_action_can_only_be_consumed_once(
    decision_fixture,
):

    async with async_session() as session:

        engine = SecurityDecisionEngine(
            session
        )

        action = _action(
            decision_fixture
        )

        result = await engine.authorize(
            action,
            require_human_approval=True,
        )

        assert result.approval_id is not None

        await session.commit()

        await engine.decide(
            approval_id=result.approval_id,
            tenant_id=decision_fixture["tenant_id"],
            approver_user_id=decision_fixture["user_id"],
            approve=True,
            reason="approved",
        )

        await session.commit()

        consumed = await engine.consume(
            approval_id=result.approval_id,
            tenant_id=decision_fixture["tenant_id"],
            expected_action_fingerprint=(
                action.fingerprint()
            ),
        )

        assert consumed.state == (
            ApprovalState.CONSUMED.value
        )

        await session.commit()

        with pytest.raises(
            ValueError,
            match="approval_not_consumable:consumed",
        ):

            await engine.consume(
                approval_id=result.approval_id,
                tenant_id=decision_fixture["tenant_id"],
                expected_action_fingerprint=(
                    action.fingerprint()
                ),
            )


@pytest.mark.asyncio
async def test_expired_approval_cannot_be_consumed(
    decision_fixture,
):

    async with async_session() as session:

        engine = SecurityDecisionEngine(
            session,
            approval_ttl_seconds=1,
        )

        action = _action(
            decision_fixture
        )

        result = await engine.authorize(
            action,
            require_human_approval=True,
        )

        assert result.approval_id is not None

        await session.commit()

        approval = await engine.get_approval(
            result.approval_id,
            decision_fixture["tenant_id"],
        )

        assert approval is not None

        approval.expires_at = (
            approval.requested_at
            - timedelta(seconds=1)
        )

        await session.commit()

        with pytest.raises(
            ValueError,
            match="approval_not_pending|approval_expired",
        ):

            await engine.decide(
                approval_id=result.approval_id,
                tenant_id=decision_fixture["tenant_id"],
                approver_user_id=decision_fixture["user_id"],
                approve=True,
                reason="too late",
            )