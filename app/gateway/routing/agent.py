"""
AURAGENT agent routing.

Agent routing submits work to the Runtime heartbeat.

Cross-agent execution is intentionally restricted here.

Phase 4 will introduce cryptographic delegation/capability attenuation.
Until then, an authenticated agent may only address itself.
"""

from __future__ import annotations

import uuid

from sqlalchemy import or_, select

from app.db.models import Agent
from app.db.session import async_session
from app.runtime.bootstrap import (
    get_runtime_engine,
)
from app.runtime.tasks import TaskSpec


class AgentRouteError(RuntimeError):
    pass


class AgentRouter:
    async def resolve(
        self,
        *,
        tenant_id: uuid.UUID,
        name: str,
    ) -> Agent:
        agent_uuid: uuid.UUID | None = None

        try:
            agent_uuid = uuid.UUID(
                name
            )
        except ValueError:
            pass

        async with async_session() as session:
            if agent_uuid is not None:
                query = (
                    select(Agent)
                    .where(
                        Agent.agent_id
                        == agent_uuid
                    )
                    .where(
                        Agent.tenant_id
                        == tenant_id
                    )
                )
            else:
                query = (
                    select(Agent)
                    .where(
                        Agent.name
                        == name
                    )
                    .where(
                        Agent.tenant_id
                        == tenant_id
                    )
                    .order_by(
                        Agent.created_at.asc()
                    )
                    .limit(2)
                )

            rows = (
                await session.execute(
                    query
                )
            ).scalars().all()

        if not rows:
            raise AgentRouteError(
                "agent_route_not_found"
            )

        if (
            agent_uuid is None
            and len(rows) > 1
        ):
            raise AgentRouteError(
                "agent_route_name_ambiguous"
            )

        agent = rows[0]

        if agent.status != "active":
            raise AgentRouteError(
                "agent_route_inactive"
            )

        return agent

    async def dispatch(
        self,
        *,
        tenant_id: uuid.UUID,
        caller_agent_id: uuid.UUID,
        target_name: str,
        trace_id: str,
        payload,
        metadata: dict,
    ) -> dict:
        target = await self.resolve(
            tenant_id=tenant_id,
            name=target_name,
        )

        if (
            target.agent_id
            != caller_agent_id
        ):
            raise AgentRouteError(
                "cross_agent_route_requires_delegation"
            )

        engine = await get_runtime_engine()

        spec = TaskSpec(
            tenant_id=tenant_id,
            agent_id=target.agent_id,
            kind="gateway.agent.dispatch",
            payload=payload,
            metadata={
                **metadata,
                "gateway_target_agent": str(
                    target.agent_id
                ),
            },
            trace_id=trace_id,
        )

        record = await engine.submit_task(
            spec
        )

        return {
            "status": "accepted",
            "task_id": str(
                record.task_id
            ),
            "agent_id": str(
                target.agent_id
            ),
            "trace_id": trace_id,
            "payload_hash": (
                spec.payload_hash
            ),
        }