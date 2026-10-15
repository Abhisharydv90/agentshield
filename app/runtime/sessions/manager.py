"""
AURAGENT runtime execution-session manager.

This is NOT the authentication/browser session system.

Runtime sessions belong to autonomous execution.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class RuntimeSessionHandle:
    session_id: uuid.UUID
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    trace_id: str
    created_at: datetime


class SessionManager:
    """
    Durable runtime session facade.
    """

    def __init__(self, store) -> None:
        self.store = store

    async def create(
        self,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        trace_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> RuntimeSessionHandle:
        if not trace_id:
            raise ValueError(
                "runtime_session_trace_required"
            )

        if len(trace_id) > 128:
            raise ValueError(
                "runtime_session_trace_too_long"
            )

        session_id = uuid.uuid4()

        await self.store.create_session(
            session_id=session_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            trace_id=trace_id,
            metadata=dict(
                metadata or {}
            ),
        )

        await self.store.append_runtime_event(
            tenant_id=tenant_id,
            trace_id=trace_id,
            event_type="session.created",
            payload_hash=None,
            metadata={
                "session_id": str(
                    session_id
                ),
                "agent_id": str(
                    agent_id
                ),
            },
            session_id=session_id,
            idempotency_key=(
                f"session-created:{session_id}"
            ),
        )

        return RuntimeSessionHandle(
            session_id=session_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            trace_id=trace_id,
            created_at=utc_now(),
        )

    async def get(
        self,
        *,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ):
        return await self.store.get_session(
            tenant_id,
            session_id,
        )

    async def close(
        self,
        *,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> None:
        session = await self.store.get_session(
            tenant_id,
            session_id,
        )

        if session is None:
            return

        await self.store.close_session(
            tenant_id,
            session_id,
        )

        trace_id = getattr(
            session,
            "trace_id",
            None,
        )

        if trace_id is None and isinstance(
            session,
            dict,
        ):
            trace_id = session.get(
                "trace_id",
                str(session_id),
            )

        await self.store.append_runtime_event(
            tenant_id=tenant_id,
            trace_id=trace_id or str(session_id),
            event_type="session.closed",
            payload_hash=None,
            metadata={
                "session_id": str(
                    session_id
                )
            },
            session_id=session_id,
            idempotency_key=(
                f"session-closed:{session_id}"
            ),
        )