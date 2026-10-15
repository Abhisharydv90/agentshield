"""
Human approval control plane.

This API is intentionally separate from the runtime API.

Rules:
    - Only an authenticated human browser session may access it.
    - Only tenant owners/admins may read or decide approvals.
    - Agent API keys are never accepted as human principals.
    - A decision endpoint accepts only approve/deny + a reason.
      The action itself comes only from the persisted approval record.
    - The exact persisted action payload and fingerprint are returned for
      inspection, making the human decision explicit and auditable.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, select

from app.db.models import ApprovalRequest, Tenant, User
from app.db.session import async_session
from app.security.authorization import require_permission
from app.security.decision.contract import ApprovalState
from app.security.decision.engine import SecurityDecisionEngine


router = APIRouter(
    prefix="/api/approvals",
    tags=["approvals"],
)


# ============================================================
# Schemas
# ============================================================


class ApprovalSummary(BaseModel):
    """Queue-safe approval representation without action arguments."""

    approval_id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    trace_id: str
    action_fingerprint: str
    policy_version: str
    policy_hash: str
    capability_snapshot_hash: str
    decision_hash: str
    state: str
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    decided_by_user_id: uuid.UUID | None
    decision_reason: str | None


class ApprovalDetail(ApprovalSummary):
    """Full persisted action for human inspection."""

    action_payload: dict[str, Any]


class ApprovalListResponse(BaseModel):
    items: list[ApprovalSummary]
    count: int


class ApprovalDecisionRequest(BaseModel):
    """The action being approved is deliberately NOT client supplied."""

    approve: bool
    reason: str = Field(
        default="",
        max_length=500,
    )


# ============================================================
# Security helpers
# ============================================================


def _require_human(
    request: Request,
    permission: str,
) -> tuple[User, Tenant]:
    """
    Require a live browser session belonging to the current tenant.

    API keys, dev fallback principals, anonymous callers, and cross-tenant
    state are rejected before the business permission is evaluated.
    """

    auth_type = getattr(
        request.state,
        "auth_type",
        None,
    )
    user = getattr(
        request.state,
        "user",
        None,
    )
    tenant = getattr(
        request.state,
        "tenant",
        None,
    )

    if auth_type != "session" or user is None or tenant is None:
        raise HTTPException(
            status_code=403,
            detail="human_session_required",
        )

    if user.status != "active" or tenant.status != "active":
        raise HTTPException(
            status_code=401,
            detail="principal_inactive",
        )

    if user.tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="tenant_mismatch",
        )

    require_permission(
        user.role,
        permission,
    )

    return user, tenant


# ============================================================
# Serialization
# ============================================================


def _summary(
    approval: ApprovalRequest,
) -> ApprovalSummary:
    return ApprovalSummary(
        approval_id=approval.approval_id,
        tenant_id=approval.tenant_id,
        agent_id=approval.agent_id,
        trace_id=approval.trace_id,
        action_fingerprint=approval.action_fingerprint,
        policy_version=approval.policy_version,
        policy_hash=approval.policy_hash,
        capability_snapshot_hash=approval.capability_snapshot_hash,
        decision_hash=approval.decision_hash,
        state=approval.state,
        requested_at=approval.requested_at,
        expires_at=approval.expires_at,
        decided_at=approval.decided_at,
        decided_by_user_id=approval.decided_by_user_id,
        decision_reason=approval.decision_reason,
    )


def _detail(
    approval: ApprovalRequest,
) -> ApprovalDetail:
    return ApprovalDetail(
        **_summary(approval).model_dump(),
        action_payload=approval.action_payload,
    )


# ============================================================
# List
# ============================================================


@router.get(
    "",
    response_model=ApprovalListResponse,
)
async def list_approvals(
    request: Request,
    response: Response,
    state: ApprovalState | None = Query(
        default=ApprovalState.PENDING,
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
) -> ApprovalListResponse:
    """List approvals for the current tenant."""

    _, tenant = _require_human(
        request,
        "tenant.approvals.read",
    )
    response.headers["Cache-Control"] = "no-store"

    async with async_session() as session:
        stmt = (
            select(ApprovalRequest)
            .where(
                ApprovalRequest.tenant_id
                == tenant.tenant_id
            )
            .order_by(
                desc(ApprovalRequest.requested_at)
            )
            .limit(limit)
        )

        if state is not None:
            stmt = stmt.where(
                ApprovalRequest.state
                == state.value
            )

        result = await session.execute(stmt)
        approvals = result.scalars().all()

    return ApprovalListResponse(
        items=[
            _summary(item)
            for item in approvals
        ],
        count=len(approvals),
    )


# ============================================================
# Get one
# ============================================================


@router.get(
    "/{approval_id}",
    response_model=ApprovalDetail,
)
async def get_approval(
    approval_id: uuid.UUID,
    request: Request,
    response: Response,
) -> ApprovalDetail:
    """Return the exact persisted action for human inspection."""

    _, tenant = _require_human(
        request,
        "tenant.approvals.read",
    )
    response.headers["Cache-Control"] = "no-store"

    async with async_session() as session:
        approval = (
            await SecurityDecisionEngine(
                session
            ).get_approval(
                approval_id,
                tenant.tenant_id,
            )
        )

    if approval is None:
        # Do not reveal whether the approval exists in another tenant.
        raise HTTPException(
            status_code=404,
            detail="approval_not_found",
        )

    return _detail(approval)


# ============================================================
# Decide
# ============================================================


@router.post(
    "/{approval_id}/decision",
    response_model=ApprovalDetail,
)
async def decide_approval(
    approval_id: uuid.UUID,
    payload: ApprovalDecisionRequest,
    request: Request,
    response: Response,
) -> ApprovalDetail:
    """
    Approve or deny one persisted action.

    The request body cannot replace tool name, arguments, capabilities,
    target, provenance, or fingerprint. Those values are immutable for the
    purpose of the human decision because they come from the DB record.
    """

    user, tenant = _require_human(
        request,
        "tenant.approvals.decide",
    )
    response.headers["Cache-Control"] = "no-store"

    async with async_session() as session:
        engine = SecurityDecisionEngine(
            session
        )

        try:
            approval = await engine.decide(
                approval_id=approval_id,
                tenant_id=tenant.tenant_id,
                approver_user_id=user.user_id,
                approve=payload.approve,
                reason=payload.reason.strip(),
            )

        except ValueError as exc:
            code = str(exc)

            if code == "approval_expired":
                # The engine deliberately persists the expiration transition.
                await session.commit()
                raise HTTPException(
                    status_code=410,
                    detail="approval_expired",
                ) from exc

            await session.rollback()

            if code == "approval_not_found":
                raise HTTPException(
                    status_code=404,
                    detail="approval_not_found",
                ) from exc

            if code.startswith("approval_not_pending:"):
                raise HTTPException(
                    status_code=409,
                    detail=code,
                ) from exc

            raise HTTPException(
                status_code=409,
                detail="approval_decision_rejected",
            ) from exc

        await session.commit()

    return _detail(approval)