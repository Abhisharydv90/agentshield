"""Non-executable containment planning.

This layer proposes bounded, reversible responses. It never runs commands,
kills processes, changes production credentials, or directly mutates tools.
"""

from __future__ import annotations

import hashlib
import json
from uuid import UUID, uuid4

from .contracts import ContainmentAction, ContainmentMode, ContainmentPlan


def build_containment_plan(
    *,
    tenant_id: UUID,
    trace_id: str,
    subject_id: str,
    reason: str,
    severity: str,
    evidence_present: bool,
    authority_violation: bool = False,
    approval_bypass: bool = False,
) -> ContainmentPlan | None:
    if not evidence_present:
        return None

    actions: list[ContainmentAction] = []
    normalized = severity.casefold().strip()

    if authority_violation:
        actions.append(
            ContainmentAction(
                mode=ContainmentMode.REVOKE_DELEGATION,
                subject_id=subject_id,
                reason="authority-conservation invariant violation",
                requires_human_approval=False,
                reversible=True,
            )
        )

    if normalized in {"critical", "high"}:
        actions.append(
            ContainmentAction(
                mode=ContainmentMode.QUARANTINE,
                subject_id=subject_id,
                reason=reason,
                requires_human_approval=False,
                reversible=True,
            )
        )
        actions.append(
            ContainmentAction(
                mode=ContainmentMode.REQUIRE_HUMAN,
                subject_id=subject_id,
                reason="high-severity containment requires human oversight",
                requires_human_approval=True,
                reversible=True,
            )
        )

    if approval_bypass:
        actions.append(
            ContainmentAction(
                mode=ContainmentMode.DISABLE_TOOL,
                subject_id=subject_id,
                reason="human-approval bypass detected",
                requires_human_approval=False,
                reversible=True,
            )
        )

    if not actions:
        actions.append(
            ContainmentAction(
                mode=ContainmentMode.OBSERVE,
                subject_id=subject_id,
                reason=reason,
                requires_human_approval=False,
                reversible=True,
            )
        )

    plan_id = uuid4()
    canonical = {
        "plan_id": str(plan_id),
        "tenant_id": str(tenant_id),
        "trace_id": trace_id,
        "subject_id": subject_id,
        "trigger": reason,
        "actions": [action.model_dump(mode="json") for action in actions],
        "autonomous_execution_allowed": False,
    }
    plan_hash = hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()

    return ContainmentPlan(
        plan_id=plan_id,
        tenant_id=tenant_id,
        trace_id=trace_id,
        actions=actions,
        trigger=reason,
        autonomous_execution_allowed=False,
        plan_hash=plan_hash,
    )
