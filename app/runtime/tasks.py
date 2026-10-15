"""
AURAGENT runtime task contracts.

Tasks are the smallest durable unit of autonomous execution.

Security boundary:
- payload is treated as opaque runtime data;
- persistence should use payload_hash/payload_ref;
- runtime code must not assume payloads are safe;
- authorization belongs to the Trust/Security Kernel;
- execution belongs to the task executor supplied by the caller.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping


class TaskStatus(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    RETRYING = "retrying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


TERMINAL_TASK_STATUSES = {
    TaskStatus.SUCCEEDED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
}

READY_TASK_STATUSES = {
    TaskStatus.CREATED,
    TaskStatus.RETRYING,
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_hash(value: Any) -> str:
    """
    Deterministic SHA-256 hash.

    This is used for integrity references, not confidentiality.
    """

    body = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """
    Immutable task submission contract.
    """

    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    kind: str

    payload: Any = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    session_id: uuid.UUID | None = None
    workflow_run_id: uuid.UUID | None = None
    workflow_step_key: str | None = None

    trace_id: str | None = None
    priority: int = 0

    timeout_seconds: int = 300
    max_attempts: int = 3

    idempotency_key: str | None = None

    task_id: uuid.UUID = field(default_factory=uuid.uuid4)
    created_at: datetime = field(default_factory=utc_now)

    payload_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.kind.strip():
            raise ValueError("task_kind_required")

        if len(self.kind) > 160:
            raise ValueError("task_kind_too_long")

        if self.trace_id is not None and len(self.trace_id) > 128:
            raise ValueError("trace_id_too_long")

        if not -100_000 <= self.priority <= 100_000:
            raise ValueError("priority_out_of_range")

        if not 1 <= self.timeout_seconds <= 86_400:
            raise ValueError("timeout_seconds_out_of_range")

        if not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts_out_of_range")

    @property
    def effective_trace_id(self) -> str:
        return self.trace_id or str(self.task_id)

    @property
    def payload_hash(self) -> str:
        return canonical_hash(self.payload)


@dataclass(slots=True)
class TaskRecord:
    """
    Mutable runtime representation of a persisted task.
    """

    spec: TaskSpec

    status: TaskStatus = TaskStatus.CREATED
    attempt_count: int = 0

    result: Any = None
    result_hash: str | None = None

    last_error_code: str | None = None

    available_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    latest_checkpoint_sequence: int = 0

    version: int = 0

    @property
    def task_id(self) -> uuid.UUID:
        return self.spec.task_id

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.spec.tenant_id

    @property
    def agent_id(self) -> uuid.UUID:
        return self.spec.agent_id

    @property
    def trace_id(self) -> str:
        return self.spec.effective_trace_id

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_TASK_STATUSES

    @property
    def expires_at(self) -> datetime | None:
        if self.started_at is None:
            return None

        return self.started_at + timedelta(
            seconds=self.spec.timeout_seconds
        )


def build_task_metadata(spec: TaskSpec) -> dict[str, Any]:
    """
    Create persistence-safe metadata.

    Raw payload is deliberately excluded.
    """

    metadata = dict(spec.metadata)

    metadata.setdefault(
        "payload_hash",
        spec.payload_hash,
    )

    if spec.payload_ref:
        metadata.setdefault(
            "payload_ref",
            spec.payload_ref,
        )

    return metadata