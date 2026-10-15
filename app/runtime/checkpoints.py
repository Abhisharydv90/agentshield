"""
AURAGENT checkpoint manager.

Checkpoints provide recovery points without requiring raw runtime state
to live in the SQL runtime tables.

The state digest commits to the exact state supplied by the runtime.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.runtime.tasks import canonical_hash


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class Checkpoint:
    checkpoint_id: uuid.UUID
    tenant_id: uuid.UUID
    task_id: uuid.UUID
    sequence: int
    state_hash: str
    metadata: dict[str, Any]
    created_at: datetime = field(
        default_factory=utc_now
    )


class CheckpointManager:
    """
    Runtime checkpoint facade.

    `store` must implement:

        create_checkpoint(...)
        latest_checkpoint(...)
        list_checkpoints(...)
    """

    def __init__(self, store) -> None:
        self.store = store

    async def create(
        self,
        *,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        state: Any,
        sequence: int,
        metadata: dict[str, Any] | None = None,
    ) -> Checkpoint:
        if sequence < 0:
            raise ValueError("checkpoint_sequence_invalid")

        checkpoint = Checkpoint(
            checkpoint_id=uuid.uuid4(),
            tenant_id=tenant_id,
            task_id=task_id,
            sequence=sequence,
            state_hash=canonical_hash(state),
            metadata=dict(metadata or {}),
        )

        await self.store.create_checkpoint(
            checkpoint
        )

        return checkpoint

    async def latest(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> Checkpoint | None:
        return await self.store.latest_checkpoint(
            tenant_id,
            task_id,
        )

    async def history(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        *,
        limit: int = 50,
    ) -> list[Checkpoint]:
        return await self.store.list_checkpoints(
            tenant_id,
            task_id,
            limit=limit,
        )