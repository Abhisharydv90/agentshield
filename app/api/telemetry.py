"""
Telemetry API — read-only endpoints powering the dashboard.
Every query is scoped to the authenticated tenant.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select, func, desc

from app.db.session import async_session
from app.db.models import SecurityEvent
from app.telemetry.audit import verify_chain

router = APIRouter(prefix="/api", tags=["telemetry"])


def _require_tenant(request: Request):
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(status_code=401, detail="no_tenant")
    return tenant


@router.get("/metrics")
async def get_metrics(request: Request):
    tenant = _require_tenant(request)
    async with async_session() as session:
        # Total events for this tenant
        total = await session.scalar(
            select(func.count()).select_from(SecurityEvent)
            .where(SecurityEvent.tenant_id == tenant.tenant_id)
        )

        # Blocks count
        blocks = await session.scalar(
            select(func.count()).select_from(SecurityEvent)
            .where(SecurityEvent.tenant_id == tenant.tenant_id)
            .where(SecurityEvent.action_taken == "blocked")
        )

        # Category breakdown
        stmt = (
            select(
                SecurityEvent.threat_category,
                func.count(SecurityEvent.event_id).label("count"),
            )
            .where(SecurityEvent.tenant_id == tenant.tenant_id)
            .group_by(SecurityEvent.threat_category)
        )
        rows = (await session.execute(stmt)).all()
        categories = {row.threat_category: row.count for row in rows}

        return {
            "tenant": tenant.slug,
            "total_events": total or 0,
            "total_blocks": blocks or 0,
            "by_category": categories,
        }


@router.get("/events")
async def get_events(request: Request, limit: int = 50):
    tenant = _require_tenant(request)
    limit = max(1, min(limit, 500))

    async with async_session() as session:
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.tenant_id == tenant.tenant_id)
            .order_by(desc(SecurityEvent.timestamp))
            .limit(limit)
        )
        events = (await session.execute(stmt)).scalars().all()

        return [
            {
                "event_id": str(e.event_id),
                "request_id": e.request_id,
                "timestamp": e.timestamp.isoformat(),
                "threat_category": e.threat_category,
                "action_taken": e.action_taken,
                "evaluator_reasoning": e.evaluator_reasoning,
                "record_hash": e.record_hash,
            }
            for e in events
        ]


@router.get("/audit/verify")
async def verify_audit_chain(request: Request):
    """Verify the tenant's full hash chain. Returns {valid, length, broken_at}."""
    tenant = _require_tenant(request)
    async with async_session() as session:
        result = await verify_chain(session, tenant.tenant_id)
        return {"tenant": tenant.slug, **result}