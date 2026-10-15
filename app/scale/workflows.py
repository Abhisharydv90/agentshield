"""Durable workflow envelope contracts for scaled workers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class WorkflowConflict(ValueError):
    pass


@dataclass(frozen=True)
class WorkflowCheckpoint:
    workflow_id: str
    version: int
    state: str
    state_digest: str
    updated_at: datetime


def state_digest(state: dict[str, Any]) -> str:
    encoded = json.dumps(
        state,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class InMemoryWorkflowStore:
    """Reference checkpoint store.

    A production deployment should back this contract with the existing
    durable database/runtime store; callers should not depend on this class.
    """

    def __init__(self) -> None:
        self._states: dict[str, WorkflowCheckpoint] = {}

    async def save(
        self,
        *,
        workflow_id: str,
        expected_version: int,
        state: str,
        state_data: dict[str, Any],
    ) -> WorkflowCheckpoint:
        existing = self._states.get(workflow_id)
        current_version = existing.version if existing else 0

        if current_version != expected_version:
            raise WorkflowConflict(
                f"workflow version conflict: expected {expected_version}, "
                f"actual {current_version}"
            )

        checkpoint = WorkflowCheckpoint(
            workflow_id=workflow_id,
            version=current_version + 1,
            state=state,
            state_digest=state_digest(state_data),
            updated_at=datetime.now(timezone.utc),
        )
        self._states[workflow_id] = checkpoint
        return checkpoint

    async def get(self, workflow_id: str) -> WorkflowCheckpoint | None:
        return self._states.get(workflow_id)
