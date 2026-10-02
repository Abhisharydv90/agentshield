"""
Rehydration — restores original PII values at the final edge.
CRITICAL: Only called for user-facing responses. Never for logs, caches, or tool calls.
"""
from __future__ import annotations

import uuid

from app.db.session import async_session
from app.security.pii.vault import vault
from app.telemetry.audit import write_event


async def safe_rehydrate(
    text: str,
    trace_id: str,
    tenant: str,
    destination: str = "user_response",
) -> str:
    """
    Rehydrates placeholders ONLY when the destination is user_response.
    Every rehydration is logged as a mandatory security evidence record.
    """
    if destination != "user_response":
        raise RuntimeError(f"rehydration_denied_destination:{destination}")

    try:
        tenant_id = uuid.UUID(str(tenant))
    except (ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError("rehydration_invalid_tenant_id") from exc

    restored = await vault.rehydrate(text, trace_id, tenant)

    try:
        async with async_session() as session:
            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=trace_id,
                threat_category="pii_leak",
                action_taken="rehydrated",
                evaluator_reasoning=f"rehydrated_for:{destination}",
            )
    except Exception as exc:
        raise RuntimeError("security_audit_unavailable") from exc

    return restored
