"""
Security Decision Engine integration tests for the existing judge pipeline.

These tests prove that supplying an Agent identity makes the persisted
Security Decision Engine authoritative before policy/Judge execution.
"""

from __future__ import annotations

import uuid

import pytest

from app.config import settings
from app.db.models import Agent, Tenant
from app.db.session import async_session
from app.policy.dsl import EXAMPLE_POLICY
from app.security.judge.evaluate import (
    execute_tool_with_judge,
)


@pytest.fixture
async def decision_pipeline_fixture():

    async with async_session() as session:

        tenant = Tenant(
            slug=(
                "pipeline-"
                f"{uuid.uuid4().hex[:10]}"
            ),
            name="Decision Pipeline Test",
        )

        session.add(
            tenant
        )

        await session.flush()

        authorized_agent = Agent(
            tenant_id=tenant.tenant_id,
            name="Authorized Pipeline Agent",
            description="Has database read access.",
            scopes=[
                "agent:invoke",
                "tool:read",
            ],
            status="active",
        )

        restricted_agent = Agent(
            tenant_id=tenant.tenant_id,
            name="Restricted Pipeline Agent",
            description="Cannot read tools.",
            scopes=[
                "agent:invoke",
            ],
            status="active",
        )

        session.add_all(
            [
                authorized_agent,
                restricted_agent,
            ]
        )

        await session.commit()

        fixture = {
            "tenant_id": tenant.tenant_id,
            "authorized_agent_id": (
                authorized_agent.agent_id
            ),
            "restricted_agent_id": (
                restricted_agent.agent_id
            ),
        }

    yield fixture

    async with async_session() as session:

        tenant = await session.get(
            Tenant,
            fixture["tenant_id"],
        )

        if tenant is not None:
            await session.delete(
                tenant
            )

        await session.commit()


def _read_tool_call() -> dict:

    return {
        "name": "db.query",
        "args": {
            "query": (
                "SELECT * "
                "FROM billing_invoices"
            ),
            "table": "billing_invoices",
        },
    }


@pytest.mark.asyncio
async def test_decision_engine_authorizes_active_agent(
    decision_pipeline_fixture,
    monkeypatch,
):
    """
    A DB-backed Agent with tool:read must be able to reach the
    deterministic policy layer.
    """

    monkeypatch.setattr(
        settings,
        "JUDGE_ENFORCE",
        False,
    )

    result = await execute_tool_with_judge(
        raw_tool_call=_read_tool_call(),
        policy=EXAMPLE_POLICY,
        policy_version="1.0.0",
        tenant_id=(
            decision_pipeline_fixture[
                "tenant_id"
            ]
        ),
        trace_id="pipeline-authorized",
        agent_id=(
            decision_pipeline_fixture[
                "authorized_agent_id"
            ]
        ),
    )

    assert result["decision"] == "allow"

    assert result["policy_version"] == (
        "1.0.0"
    )


@pytest.mark.asyncio
async def test_decision_engine_blocks_missing_capability_before_policy(
    decision_pipeline_fixture,
    monkeypatch,
):
    """
    An Agent missing tool:read must be blocked by the security kernel.

    The request must not proceed to the policy/Judge layers.
    """

    monkeypatch.setattr(
        settings,
        "JUDGE_ENFORCE",
        False,
    )

    result = await execute_tool_with_judge(
        raw_tool_call=_read_tool_call(),
        policy=EXAMPLE_POLICY,
        policy_version="1.0.0",
        tenant_id=(
            decision_pipeline_fixture[
                "tenant_id"
            ]
        ),
        trace_id="pipeline-restricted",
        agent_id=(
            decision_pipeline_fixture[
                "restricted_agent_id"
            ]
        ),
    )

    assert result["decision"] == "deny"

    assert result["category"] == (
        "privilege_escalation"
    )

    assert result["reason"].startswith(
        "missing_capabilities:"
    )

    assert "tool:read" in (
        result["missing_capabilities"]
    )