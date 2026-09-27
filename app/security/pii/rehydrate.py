"""
Rehydration — restores original PII values at the final edge.
CRITICAL: Only called for user-facing responses. Never for logs, caches, or tool calls.
"""
from app.security.pii.vault import vault
from app.telemetry.audit import write_event
from app.db.session import async_session


async def safe_rehydrate(
    text: str,
    trace_id: str,
    tenant: str = "default",
    destination: str = "user_response",
) -> str:
    """
    Rehydrates placeholders ONLY when the destination is user_response.
    Every rehydration is logged for compliance.
    """
    if destination != "user_response":
        raise RuntimeError(f"rehydration_denied_destination:{destination}")

    restored = await vault.rehydrate(text, trace_id, tenant)

    # Audit log: every rehydration event is recorded
    try:
        async with async_session() as session:
            await write_event(
                session=session,
                request_id=trace_id,
                threat_category="pii_leak",
                action_taken="rehydrated",
                evaluator_reasoning=f"rehydrated_for:{destination}",
            )
    except Exception as e:
        # Never let an audit failure crash the response
        print(f"WARN: rehydrate audit log failed: {e}")

    return restored