"""Tests for the human approval control plane."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from fastapi import HTTPException, Request, Response

from app.api.approvals import (
    ApprovalDecisionRequest,
    decide_approval,
    get_approval,
    list_approvals,
)
from app.config import settings
from app.db.models import APIKey, Agent, Tenant, User
from app.db.session import async_session
from app.security.api_keys import generate_key, hash_key, key_prefix
from app.security.decision.contract import (
    ApprovalState,
    SecurityAction,
    utc_now,
)
from app.security.decision.engine import SecurityDecisionEngine
from app.security.passwords import hash_password
from app.security.sessions import create_session_token, COOKIE_NAME


pytestmark = pytest.mark.asyncio


async def _create_context(
    role: str = "owner",
    *,
    with_api_key: bool = False,
):
    async with async_session() as session:
        tenant = Tenant(
            slug=f"approval-{uuid.uuid4().hex[:10]}",
            name="Approval Test Tenant",
            status="active",
        )
        session.add(tenant)
        await session.flush()

        user = User(
            tenant_id=tenant.tenant_id,
            email=f"approval-{uuid.uuid4().hex[:10]}@example.test",
            password_hash=hash_password("TestPass123"),
            name="Approval User",
            role=role,
            status="active",
            session_version=0,
        )
        session.add(user)
        await session.flush()

        agent = Agent(
            tenant_id=tenant.tenant_id,
            name="approval-agent",
            scopes=["tool:execute"],
            status="active",
        )
        session.add(agent)
        await session.flush()

        raw_key = None
        if with_api_key:
            raw_key = generate_key(live=False)
            session.add(
                APIKey(
                    tenant_id=tenant.tenant_id,
                    name="runtime-key",
                    key_prefix=key_prefix(raw_key),
                    key_hash=hash_key(raw_key),
                )
            )

        await session.commit()

    return tenant, user, agent, raw_key


def _human_request(user: User, tenant: Tenant) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/approvals",
        "headers": [],
        "state": {
            "auth_type": "session",
            "user": user,
            "tenant": tenant,
            "api_key": None,
            "agent": None,
        },
    }
    return Request(scope)


def _api_key_request(tenant: Tenant) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/approvals",
        "headers": [],
        "state": {
            "auth_type": "api_key",
            "user": None,
            "tenant": tenant,
            "api_key": object(),
            "agent": object(),
        },
    }
    return Request(scope)


async def _create_pending_approval(tenant, agent):
    action = SecurityAction(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
        trace_id=f"trace-{uuid.uuid4().hex}",
        tool_name="shell",
        operation="execute",
        target="sandbox-1",
        arguments={"command": "echo approved"},
        capabilities=["tool:execute"],
        policy_version="policy-7",
        provenance={"source": "test"},
    )

    async with async_session() as session:
        result = await SecurityDecisionEngine(session).authorize(
            action,
            require_human_approval=True,
        )
        await session.commit()
        return result.approval_id


async def _cleanup(tenant_id):
    async with async_session() as session:
        await session.execute(
            Tenant.__table__.delete().where(
                Tenant.tenant_id == tenant_id
            )
        )
        await session.commit()


async def test_owner_can_list_and_inspect_exact_action():
    tenant, user, agent, _ = await _create_context()
    try:
        approval_id = await _create_pending_approval(tenant, agent)
        request = _human_request(user, tenant)

        listed = await list_approvals(
            request,
            Response(),
            state=ApprovalState.PENDING,
            limit=50,
        )
        assert listed.count == 1
        assert listed.items[0].approval_id == approval_id

        detail = await get_approval(
            approval_id,
            request,
            Response(),
        )
        assert detail.action_payload["tool_name"] == "shell"
        assert detail.action_payload["operation"] == "execute"
        assert detail.action_payload["arguments"] == {
            "command": "echo approved"
        }
    finally:
        await _cleanup(tenant.tenant_id)


async def test_member_cannot_read_approval_queue():
    tenant, user, agent, _ = await _create_context(role="member")
    try:
        await _create_pending_approval(tenant, agent)
        with pytest.raises(HTTPException) as exc:
            await list_approvals(
                _human_request(user, tenant),
                Response(),
                state=ApprovalState.PENDING,
                limit=50,
            )
        assert exc.value.status_code == 403
        assert exc.value.detail == "forbidden"
    finally:
        await _cleanup(tenant.tenant_id)


async def test_api_key_is_not_a_human_approver():
    tenant, user, agent, raw_key = await _create_context(with_api_key=True)
    try:
        assert raw_key
        with pytest.raises(HTTPException) as exc:
            await list_approvals(
                _api_key_request(tenant),
                Response(),
                state=ApprovalState.PENDING,
                limit=50,
            )
        assert exc.value.status_code == 403
        assert exc.value.detail == "human_session_required"
    finally:
        await _cleanup(tenant.tenant_id)


async def test_owner_approves_without_being_able_to_replace_action():
    tenant, user, agent, _ = await _create_context()
    try:
        approval_id = await _create_pending_approval(tenant, agent)
        request = _human_request(user, tenant)

        await decide_approval(
            approval_id,
            ApprovalDecisionRequest(
                approve=True,
                reason="Reviewed exact runtime action",
            ),
            request,
            Response(),
        )

        async with async_session() as session:
            approval = (
                await SecurityDecisionEngine(session).get_approval(
                    approval_id,
                    tenant.tenant_id,
                )
            )
            assert approval is not None
            assert approval.state == ApprovalState.APPROVED.value
            assert approval.decision_reason == "Reviewed exact runtime action"
            assert approval.action_payload["tool_name"] == "shell"
            assert approval.action_payload["arguments"] == {
                "command": "echo approved"
            }
    finally:
        await _cleanup(tenant.tenant_id)


async def test_second_human_decision_is_rejected():
    tenant, user, agent, _ = await _create_context()
    try:
        approval_id = await _create_pending_approval(tenant, agent)
        request = _human_request(user, tenant)

        await decide_approval(
            approval_id,
            ApprovalDecisionRequest(approve=True),
            request,
            Response(),
        )

        with pytest.raises(HTTPException) as exc:
            await decide_approval(
                approval_id,
                ApprovalDecisionRequest(approve=False, reason="too late"),
                request,
                Response(),
            )

        assert exc.value.status_code == 409
        assert exc.value.detail == "approval_not_pending:approved"
    finally:
        await _cleanup(tenant.tenant_id)


async def test_expired_pending_approval_returns_410_and_persists_expiry():
    tenant, user, agent, _ = await _create_context()
    try:
        approval_id = await _create_pending_approval(tenant, agent)

        async with async_session() as session:
            approval = (
                await SecurityDecisionEngine(session).get_approval(
                    approval_id,
                    tenant.tenant_id,
                )
            )
            assert approval is not None
            approval.expires_at = utc_now() - timedelta(seconds=1)
            await session.commit()

        with pytest.raises(HTTPException) as exc:
            await decide_approval(
                approval_id,
                ApprovalDecisionRequest(approve=True),
                _human_request(user, tenant),
                Response(),
            )

        assert exc.value.status_code == 410
        assert exc.value.detail == "approval_expired"

        async with async_session() as session:
            approval = (
                await SecurityDecisionEngine(session).get_approval(
                    approval_id,
                    tenant.tenant_id,
                )
            )
            assert approval is not None
            assert approval.state == ApprovalState.EXPIRED.value
    finally:
        await _cleanup(tenant.tenant_id)
