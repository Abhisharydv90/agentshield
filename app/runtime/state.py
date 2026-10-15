"""
AURAGENT versioned runtime state.

State mutation uses optimistic concurrency.

The runtime does not treat an untrusted model-produced state blob as
authority. State is data; authority is evaluated separately.
"""

from __future__ import annotations

import asyncio
import copy
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class StateConflict(RuntimeError):
    """Raised when optimistic state versioning detects a stale writer."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class RuntimeState:
    tenant_id: uuid.UUID
    task_id: uuid.UUID

    version: int = 0
    values: dict[str, Any] = field(default_factory=dict)

    updated_at: datetime = field(
        default_factory=utc_now
    )


class StateManager:
    """
    In-process optimistic runtime state manager.

    Durable checkpointing is provided by CheckpointManager.
    """

    def __init__(self) -> None:
        self._states: dict[tuple[uuid.UUID, uuid.UUID], RuntimeState] = {}
        self._locks: dict[tuple[uuid.UUID, uuid.UUID], asyncio.Lock] = {}
        self._registry_lock = asyncio.Lock()

    async def _lock_for(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> asyncio.Lock:
        key = (tenant_id, task_id)

        async with self._registry_lock:
            lock = self._locks.get(key)

            if lock is None:
                lock = asyncio.Lock()
                self._locks[key] = lock

            return lock

    async def get(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> RuntimeState:
        key = (tenant_id, task_id)

        async with self._lock_for(
            tenant_id,
            task_id,
        ):
            current = self._states.get(key)

            if current is None:
                current = RuntimeState(
                    tenant_id=tenant_id,
                    task_id=task_id,
                )
                self._states[key] = current

            return copy.deepcopy(current)

    async def replace(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        values: dict[str, Any],
        *,
        expected_version: int,
    ) -> RuntimeState:
        key = (tenant_id, task_id)

        async with self._lock_for(
            tenant_id,
            task_id,
        ):
            current = self._states.get(key)

            if current is None:
                current = RuntimeState(
                    tenant_id=tenant_id,
                    task_id=task_id,
                )

            if current.version != expected_version:
                raise StateConflict(
                    f"expected={expected_version}, "
                    f"actual={current.version}"
                )

            current = RuntimeState(
                tenant_id=tenant_id,
                task_id=task_id,
                version=current.version + 1,
                values=copy.deepcopy(values),
                updated_at=utc_now(),
            )

            self._states[key] = current

            return copy.deepcopy(current)

    async def patch(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        changes: dict[str, Any],
        *,
        expected_version: int,
    ) -> RuntimeState:
        current = await self.get(
            tenant_id,
            task_id,
        )

        merged = dict(current.values)
        merged.update(changes)

        return await self.replace(
            tenant_id,
            task_id,
            merged,
            expected_version=expected_version,
        )

    async def delete(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> None:
        key = (tenant_id, task_id)

        async with self._lock_for(
            tenant_id,
            task_id,
        ):
            self._states.pop(
                key,
                None,
            )