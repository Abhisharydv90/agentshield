"""
Persisted Security Decision Engine.

Responsibilities:

    1. Produce deterministic decisions.
    2. Create durable human-approval requests.
    3. Prevent approval replay.
    4. Enforce approval expiration.
    5. Bind approval to the exact action fingerprint.
    6. Permit exactly one successful consumption.

This is intentionally database-backed. An approval that only exists in
process memory is not sufficient for a distributed autonomous-agent
runtime.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Agent, ApprovalRequest
from app.security.capabilities import (
    missing_capabilities,
    required_capabilities_for_operation,
)
from app.security.decision.contract import (
    ApprovalState,
    SecurityAction,
    SecurityDecision,
    utc_now,
)


# ============================================================
# Result
# ============================================================


class DecisionResult:
    """
    Structured result returned by the decision engine.
    """

    def __init__(
        self,
        *,
        decision: SecurityDecision,
        reason: str,
        action_fingerprint: str,
        approval_id: uuid.UUID | None = None,
        missing_capabilities: list[str] | None = None,
    ) -> None:

        self.decision = decision
        self.reason = reason
        self.action_fingerprint = action_fingerprint
        self.approval_id = approval_id
        self.missing_capabilities = (
            missing_capabilities or []
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "action_fingerprint": (
                self.action_fingerprint
            ),
            "approval_id": (
                str(self.approval_id)
                if self.approval_id
                else None
            ),
            "missing_capabilities": (
                self.missing_capabilities
            ),
        }


# ============================================================
# Engine
# ============================================================


class SecurityDecisionEngine:
    """
    Database-backed authorization and approval engine.

    The first version intentionally focuses on the hard security
    primitive: an approval is a durable, expiring, one-time capability
    to authorize one exact action.
    """

    def __init__(
        self,
        session: AsyncSession,
        approval_ttl_seconds: int = 300,
    ) -> None:

        if approval_ttl_seconds <= 0:
            raise ValueError(
                "approval_ttl_seconds must be greater than zero"
            )

        self.session = session
        self.approval_ttl = timedelta(
            seconds=approval_ttl_seconds
        )

    # --------------------------------------------------------
    # Agent authorization
    # --------------------------------------------------------

    async def _load_agent(
        self,
        action: SecurityAction,
    ) -> Agent | None:

        result = await self.session.execute(
            select(Agent)
            .where(
                Agent.agent_id
                == action.agent_id
            )
            .where(
                Agent.tenant_id
                == action.tenant_id
            )
        )

        return result.scalar_one_or_none()

    def _agent_is_usable(
        self,
        agent: Agent | None,
    ) -> bool:

        if agent is None:
            return False

        return agent.status == "active"

    # --------------------------------------------------------
    # Deterministic decision
    # --------------------------------------------------------

    async def authorize(
        self,
        action: SecurityAction,
        *,
        require_human_approval: bool = False,
        quarantine: bool = False,
    ) -> DecisionResult:

        fingerprint = action.fingerprint()

        agent = await self._load_agent(
            action
        )

        if not self._agent_is_usable(agent):

            return DecisionResult(
                decision=SecurityDecision.DENY,
                reason="agent_unavailable",
                action_fingerprint=fingerprint,
            )

        required = (
            required_capabilities_for_operation(
                action.operation
            )
        )

        if action.operation not in {
            "read",
            "write",
            "delete",
            "execute",
            "external_call",
        }:

            return DecisionResult(
                decision=SecurityDecision.DENY,
                reason="unknown_operation",
                action_fingerprint=fingerprint,
            )

        missing = missing_capabilities(
            agent.scopes,
            required,
        )

        if missing:

            return DecisionResult(
                decision=SecurityDecision.DENY,
                reason=(
                    "missing_capabilities:"
                    + ",".join(missing)
                ),
                action_fingerprint=fingerprint,
                missing_capabilities=missing,
            )

        if quarantine:

            return DecisionResult(
                decision=SecurityDecision.QUARANTINE,
                reason="quarantine_requested",
                action_fingerprint=fingerprint,
            )

        if require_human_approval:

            approval = (
                await self._create_approval(
                    action
                )
            )

            return DecisionResult(
                decision=(
                    SecurityDecision
                    .APPROVAL_REQUIRED
                ),
                reason="human_approval_required",
                action_fingerprint=fingerprint,
                approval_id=approval.approval_id,
            )

        return DecisionResult(
            decision=SecurityDecision.ALLOW,
            reason="capability_authorized",
            action_fingerprint=fingerprint,
        )

    # --------------------------------------------------------
    # Approval creation
    # --------------------------------------------------------

    async def _create_approval(
        self,
        action: SecurityAction,
    ) -> ApprovalRequest:

        now = utc_now()

        approval = ApprovalRequest(
            approval_id=uuid.uuid4(),
            tenant_id=action.tenant_id,
            agent_id=action.agent_id,
            trace_id=action.trace_id,
            action_fingerprint=(
                action.fingerprint()
            ),
            action_payload=action.to_dict(),
            policy_version=(
                action.policy_version
            ),
            state=ApprovalState.PENDING.value,
            requested_at=now,
            expires_at=(
                now + self.approval_ttl
            ),
            decided_at=None,
            decided_by_user_id=None,
            decision_reason=None,
        )

        self.session.add(
            approval
        )

        await self.session.flush()

        return approval

    # --------------------------------------------------------
    # Approval lookup
    # --------------------------------------------------------

    async def get_approval(
        self,
        approval_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> ApprovalRequest | None:

        result = await self.session.execute(
            select(ApprovalRequest)
            .where(
                ApprovalRequest.approval_id
                == approval_id
            )
            .where(
                ApprovalRequest.tenant_id
                == tenant_id
            )
        )

        return result.scalar_one_or_none()

    # --------------------------------------------------------
    # Human decision
    # --------------------------------------------------------

    async def decide(
        self,
        *,
        approval_id: uuid.UUID,
        tenant_id: uuid.UUID,
        approver_user_id: uuid.UUID,
        approve: bool,
        reason: str = "",
    ) -> ApprovalRequest:

        now = utc_now()

        result = await self.session.execute(
            select(ApprovalRequest)
            .where(
                ApprovalRequest.approval_id
                == approval_id
            )
            .where(
                ApprovalRequest.tenant_id
                == tenant_id
            )
            .with_for_update()
        )

        approval = (
            result.scalar_one_or_none()
        )

        if approval is None:
            raise ValueError(
                "approval_not_found"
            )

        if approval.state != (
            ApprovalState.PENDING.value
        ):
            raise ValueError(
                f"approval_not_pending:{approval.state}"
            )

        if now >= approval.expires_at:

            approval.state = (
                ApprovalState.EXPIRED.value
            )
            approval.decided_at = now
            approval.decided_by_user_id = (
                approver_user_id
            )
            approval.decision_reason = (
                "approval_expired"
            )

            await self.session.flush()

            raise ValueError(
                "approval_expired"
            )

        approval.state = (
            ApprovalState.APPROVED.value
            if approve
            else ApprovalState.DENIED.value
        )

        approval.decided_at = now

        approval.decided_by_user_id = (
            approver_user_id
        )

        approval.decision_reason = (
            reason[:500]
            if reason
            else (
                "approved"
                if approve
                else "denied"
            )
        )

        await self.session.flush()

        return approval

    # --------------------------------------------------------
    # One-time consumption
    # --------------------------------------------------------

    async def consume(
        self,
        *,
        approval_id: uuid.UUID,
        tenant_id: uuid.UUID,
        expected_action_fingerprint: str,
    ) -> ApprovalRequest:

        now = utc_now()

        result = await self.session.execute(
            select(ApprovalRequest)
            .where(
                ApprovalRequest.approval_id
                == approval_id
            )
            .where(
                ApprovalRequest.tenant_id
                == tenant_id
            )
            .with_for_update()
        )

        approval = (
            result.scalar_one_or_none()
        )

        if approval is None:
            raise ValueError(
                "approval_not_found"
            )

        if approval.action_fingerprint != (
            expected_action_fingerprint
        ):
            raise ValueError(
                "approval_action_mismatch"
            )

        if approval.state != (
            ApprovalState.APPROVED.value
        ):
            raise ValueError(
                f"approval_not_consumable:{approval.state}"
            )

        if now >= approval.expires_at:

            approval.state = (
                ApprovalState.EXPIRED.value
            )
            approval.decided_at = now

            await self.session.flush()

            raise ValueError(
                "approval_expired"
            )

        # Critical replay-protection transition.
        approval.state = (
            ApprovalState.CONSUMED.value
        )

        await self.session.flush()

        return approval