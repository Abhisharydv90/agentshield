"""
Telemetry API — read-only endpoints powering the dashboard.

Every query is scoped to the authenticated tenant.

The evidence router is mounted here so the application entrypoint does not
need another phase-by-phase modification.
"""

from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
)
from sqlalchemy import (
    desc,
    func,
    select,
)

from app.db.models import SecurityEvent
from app.db.session import async_session
from app.telemetry.audit import verify_chain
from app.api.evidence import router as evidence_router


router = APIRouter(
    prefix="/api",
    tags=["telemetry"],
)


def _require_tenant(
    request: Request,
):
    tenant = getattr(
        request.state,
        "tenant",
        None,
    )

    if tenant is None:
        raise HTTPException(
            status_code=401,
            detail="no_tenant",
        )

    return tenant


@router.get("/metrics")
async def get_metrics(
    request: Request,
):
    tenant = _require_tenant(
        request
    )

    async with async_session() as session:

        total = await session.scalar(
            select(
                func.count()
            )
            .select_from(
                SecurityEvent
            )
            .where(
                SecurityEvent.tenant_id
                == tenant.tenant_id
            )
        )

        blocks = await session.scalar(
            select(
                func.count()
            )
            .select_from(
                SecurityEvent
            )
            .where(
                SecurityEvent.tenant_id
                == tenant.tenant_id
            )
            .where(
                SecurityEvent.action_taken
                == "blocked"
            )
        )

        stmt = (
            select(
                SecurityEvent.threat_category,
                func.count(
                    SecurityEvent.event_id
                ).label(
                    "count"
                ),
            )
            .where(
                SecurityEvent.tenant_id
                == tenant.tenant_id
            )
            .group_by(
                SecurityEvent.threat_category
            )
        )

        rows = (
            await session.execute(
                stmt
            )
        ).all()

        categories = {
            row.threat_category:
                row.count
            for row in rows
        }

        return {
            "tenant":
                tenant.slug,

            "total_events":
                total or 0,

            "total_blocks":
                blocks or 0,

            "by_category":
                categories,
        }


@router.get("/events")
async def get_events(
    request: Request,
    limit: int = 50,
):

    tenant = _require_tenant(
        request
    )

    limit = max(
        1,
        min(
            limit,
            500,
        ),
    )

    async with async_session() as session:

        stmt = (
            select(
                SecurityEvent
            )
            .where(
                SecurityEvent.tenant_id
                == tenant.tenant_id
            )
            .order_by(
                desc(
                    SecurityEvent.timestamp
                )
            )
            .limit(
                limit
            )
        )

        events = (
            await session.execute(
                stmt
            )
        ).scalars().all()

        return [
            {
                "event_id":
                    str(
                        event.event_id
                    ),

                "request_id":
                    event.request_id,

                "timestamp":
                    event.timestamp.isoformat(),

                "threat_category":
                    event.threat_category,

                "action_taken":
                    event.action_taken,

                "evaluator_reasoning":
                    event.evaluator_reasoning,

                "record_hash":
                    event.record_hash,
            }
            for event in events
        ]


@router.get("/audit/verify")
async def verify_audit_chain(
    request: Request,
):

    tenant = _require_tenant(
        request
    )

    async with async_session() as session:

        result = await verify_chain(
            session,
            tenant.tenant_id,
        )

        return {
            "tenant":
                tenant.slug,
            **result,
        }


# ============================================================
# Evidence Graph API
# ============================================================

router.include_router(
    evidence_router
)