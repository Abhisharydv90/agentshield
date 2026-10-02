"""
Audit concurrency tests.

Proves that concurrent writes for the same tenant serialize into
one valid hash chain.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import select

from app.db.models import SecurityEvent, Tenant
from app.db.session import async_session
from app.telemetry.audit import (
    verify_chain,
    write_event,
)


@pytest.mark.asyncio
async def test_concurrent_events_form_one_valid_chain():

    async with async_session() as session:

        tenant = Tenant(
            slug=(
                "audit-concurrency-"
                f"{uuid.uuid4().hex[:10]}"
            ),
            name="Audit Concurrency Test",
        )

        session.add(
            tenant
        )

        await session.commit()

        tenant_id = tenant.tenant_id

    async def append_event(
        number: int,
    ):

        async with async_session() as session:

            return await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=
                    f"concurrent-{number}",
                threat_category=
                    "test",
                action_taken=
                    "blocked",
                evaluator_reasoning=
                    f"concurrent event {number}",
            )

    events = await asyncio.gather(
        append_event(1),
        append_event(2),
    )

    assert len(
        events
    ) == 2

    async with async_session() as session:

        result = await verify_chain(
            session,
            tenant_id,
        )

        assert result["valid"] is True
        assert result["length"] == 2

        rows = (
            await session.execute(
                select(
                    SecurityEvent
                )
                .where(
                    SecurityEvent.tenant_id
                    == tenant_id
                )
            )
        ).scalars().all()

        assert len(rows) == 2

        # Exactly one event is the chain root.
        assert sum(
            event.prev_hash is None
            for event in rows
        ) == 1

        # Exactly one event points to the first event.
        assert sum(
            event.prev_hash is not None
            for event in rows
        ) == 1

    # Cleanup through tenant cascade.
    async with async_session() as session:

        tenant = await session.get(
            Tenant,
            tenant_id,
        )

        if tenant is not None:
            await session.delete(
                tenant
            )

        await session.commit()