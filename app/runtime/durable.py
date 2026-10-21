"""
AURAGENT durable runtime store.

Storage backends:

    InMemoryRuntimeStore
        Development/reference implementation.

    PostgresRuntimeStore
        Persistent runtime implementation.

The runtime API depends on the RuntimeStore protocol rather than
database-specific details.

This abstraction is intentionally kept stable for Phase 13 distributed
runtime scaling.
"""

from __future__ import annotations

import asyncio
import copy
import os
import uuid
from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy import and_, func, select, update
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError

from app.db.models import Agent
from app.db.runtime_models import (
    RuntimeCheckpoint,
    RuntimeEvent,
    RuntimeSession,
    RuntimeTask,
    RuntimeTaskDependency,
    WorkflowDefinition,
    WorkflowRun,
    WorkflowStep,
)
from app.db.session import async_session

from app.runtime.tasks import (
    TaskRecord,
    TaskSpec,
    TaskStatus,
    build_task_metadata,
    canonical_hash,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Store protocol
# ============================================================

class RuntimeStore(Protocol):
    """
    Persistent runtime contract.
    """

    async def create_task(
        self,
        spec: TaskSpec,
    ) -> TaskRecord:
        ...

    async def get_task(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> TaskRecord | None:
        ...

    async def save_task(
        self,
        record: TaskRecord,
    ) -> TaskRecord:
        ...

    async def list_ready_tasks(
        self,
        tenant_id: uuid.UUID,
        *,
        limit: int = 100,
    ) -> list[TaskRecord]:
        ...

    async def list_tasks_with_failed_dependencies(
        self,
        tenant_id: uuid.UUID,
    ) -> list[TaskRecord]:
        ...

    async def list_active_tenants(
        self,
    ) -> list[uuid.UUID]:
        ...

    async def add_dependency(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        depends_on_task_id: uuid.UUID,
    ) -> None:
        ...

    async def create_checkpoint(
        self,
        checkpoint,
    ) -> None:
        ...

    async def latest_checkpoint(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ):
        ...

    async def list_checkpoints(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        *,
        limit: int = 50,
    ):
        ...

    async def append_runtime_event(
        self,
        *,
        tenant_id: uuid.UUID,
        trace_id: str,
        event_type: str,
        payload_hash: str | None,
        metadata: dict,
        task_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        workflow_run_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        ...

    async def create_session(
        self,
        *,
        session_id: uuid.UUID,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        trace_id: str,
        metadata: dict,
    ) -> None:
        ...

    async def get_session(
        self,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ):
        ...

    async def close_session(
        self,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> None:
        ...

    async def create_workflow(
        self,
        *,
        workflow_id: uuid.UUID,
        tenant_id: uuid.UUID,
        name: str,
        version: str,
        definition: dict,
        steps: list,
    ) -> None:
        ...

    async def create_workflow_run(
        self,
        *,
        run_id: uuid.UUID,
        workflow_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID | None,
        trace_id: str,
        input_hash: str | None,
    ) -> None:
        ...


# ============================================================
# In-memory store
# ============================================================

class InMemoryRuntimeStore:
    """
    Reference implementation.

    Runtime state disappears when the process exits.
    """

    def __init__(self) -> None:
        self._tasks: dict[
            uuid.UUID,
            TaskRecord,
        ] = {}

        self._dependencies: dict[
            uuid.UUID,
            set[uuid.UUID],
        ] = {}

        self._checkpoints: dict[
            uuid.UUID,
            list,
        ] = {}

        self._events: list[dict] = []

        self._sessions: dict[
            uuid.UUID,
            dict,
        ] = {}

        self._workflows: dict[
            uuid.UUID,
            dict,
        ] = {}

        self._workflow_runs: dict[
            uuid.UUID,
            dict,
        ] = {}

        self._lock = asyncio.Lock()

    async def create_task(
        self,
        spec: TaskSpec,
    ) -> TaskRecord:
        async with self._lock:
            if spec.idempotency_key:
                for record in self._tasks.values():
                    if (
                        record.tenant_id
                        == spec.tenant_id
                        and record.spec.idempotency_key
                        == spec.idempotency_key
                    ):
                        return copy.deepcopy(
                            record
                        )

            record = TaskRecord(
                spec=spec,
            )

            self._tasks[
                record.task_id
            ] = copy.deepcopy(record)

            return copy.deepcopy(
                record
            )

    async def get_task(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> TaskRecord | None:
        async with self._lock:
            record = self._tasks.get(
                task_id
            )

            if record is None:
                return None

            if (
                record.tenant_id
                != tenant_id
            ):
                return None

            return copy.deepcopy(
                record
            )

    async def save_task(
        self,
        record: TaskRecord,
    ) -> TaskRecord:
        async with self._lock:
            existing = self._tasks.get(
                record.task_id
            )

            if (
                existing is not None
                and existing.tenant_id
                != record.tenant_id
            ):
                raise PermissionError(
                    "cross_tenant_task_access"
                )

            self._tasks[
                record.task_id
            ] = copy.deepcopy(
                record
            )

            return copy.deepcopy(
                record
            )

    async def list_ready_tasks(
        self,
        tenant_id: uuid.UUID,
        *,
        limit: int = 100,
    ) -> list[TaskRecord]:
        async with self._lock:
            now = utc_now()

            candidates = []

            for record in self._tasks.values():
                if (
                    record.tenant_id
                    != tenant_id
                ):
                    continue

                if record.status not in {
                    TaskStatus.CREATED,
                    TaskStatus.QUEUED,
                    TaskStatus.RETRYING,
                }:
                    continue

                if record.available_at > now:
                    continue

                dependencies = (
                    self._dependencies.get(
                        record.task_id,
                        set(),
                    )
                )

                ready = True

                for dependency_id in (
                    dependencies
                ):
                    parent = self._tasks.get(
                        dependency_id
                    )

                    if (
                        parent is None
                        or parent.status
                        != TaskStatus.SUCCEEDED
                    ):
                        ready = False
                        break

                if ready:
                    candidates.append(
                        copy.deepcopy(
                            record
                        )
                    )

            candidates.sort(
                key=lambda item: (
                    -item.spec.priority,
                    item.spec.created_at,
                )
            )

            return candidates[
                : max(1, limit)
            ]

    async def list_active_tenants(
        self,
    ) -> list[uuid.UUID]:
        async with self._lock:
            return sorted(
                {
                    record.tenant_id
                    for record in self._tasks.values()
                    if record.status
                    in {
                        TaskStatus.CREATED,
                        TaskStatus.QUEUED,
                        TaskStatus.RETRYING,
                    }
                },
                key=str,
            )

    async def list_tasks_with_failed_dependencies(
        self,
        tenant_id: uuid.UUID,
    ) -> list[TaskRecord]:
        """Return queued tasks with prerequisites that cannot succeed."""
        async with self._lock:
            failed = []
            eligible = {
                TaskStatus.CREATED,
                TaskStatus.QUEUED,
                TaskStatus.RETRYING,
            }
            terminal_failures = {
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
                TaskStatus.BLOCKED,
            }
            for task_id, dependencies in self._dependencies.items():
                child = self._tasks.get(task_id)
                if child is None or child.tenant_id != tenant_id:
                    continue
                if child.status not in eligible:
                    continue
                for dependency_id in dependencies:
                    parent = self._tasks.get(dependency_id)
                    if (
                        parent is not None
                        and parent.tenant_id == tenant_id
                        and parent.status in terminal_failures
                    ):
                        failed.append(copy.deepcopy(child))
                        break
            return failed


    async def add_dependency(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        depends_on_task_id: uuid.UUID,
    ) -> None:
        if task_id == depends_on_task_id:
            raise ValueError(
                "task_dependency_self_reference"
            )

        async with self._lock:
            task = self._tasks.get(
                task_id
            )
            parent = self._tasks.get(
                depends_on_task_id
            )

            if (
                task is None
                or parent is None
            ):
                raise KeyError(
                    "task_dependency_not_found"
                )

            if (
                task.tenant_id
                != tenant_id
                or parent.tenant_id
                != tenant_id
            ):
                raise PermissionError(
                    "cross_tenant_task_dependency"
                )

            self._dependencies.setdefault(
                task_id,
                set(),
            ).add(
                depends_on_task_id
            )

    async def create_checkpoint(
        self,
        checkpoint,
    ) -> None:
        async with self._lock:
            self._checkpoints.setdefault(
                checkpoint.task_id,
                [],
            ).append(
                checkpoint
            )

    async def latest_checkpoint(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ):
        async with self._lock:
            records = [
                item
                for item in self._checkpoints.get(
                    task_id,
                    [],
                )
                if item.tenant_id
                == tenant_id
            ]

            if not records:
                return None

            return max(
                records,
                key=lambda item: item.sequence,
            )

    async def list_checkpoints(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        *,
        limit: int = 50,
    ):
        async with self._lock:
            records = [
                item
                for item in self._checkpoints.get(
                    task_id,
                    [],
                )
                if item.tenant_id
                == tenant_id
            ]

            records.sort(
                key=lambda item: item.sequence,
                reverse=True,
            )

            return records[
                : max(1, limit)
            ]

    async def append_runtime_event(
        self,
        *,
        tenant_id: uuid.UUID,
        trace_id: str,
        event_type: str,
        payload_hash: str | None,
        metadata: dict,
        task_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        workflow_run_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        async with self._lock:
            if idempotency_key:
                for event in self._events:
                    if (
                        event[
                            "tenant_id"
                        ] == tenant_id
                        and event.get(
                            "idempotency_key"
                        )
                        == idempotency_key
                    ):
                        return

            self._events.append(
                {
                    "event_id": uuid.uuid4(),
                    "tenant_id": tenant_id,
                    "trace_id": trace_id,
                    "event_type": event_type,
                    "payload_hash": payload_hash,
                    "metadata": dict(
                        metadata
                    ),
                    "task_id": task_id,
                    "session_id": session_id,
                    "workflow_run_id": workflow_run_id,
                    "correlation_id": correlation_id,
                    "idempotency_key": idempotency_key,
                    "occurred_at": utc_now(),
                }
            )

    async def create_session(
        self,
        *,
        session_id: uuid.UUID,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        trace_id: str,
        metadata: dict,
    ) -> None:
        async with self._lock:
            self._sessions[
                session_id
            ] = {
                "session_id": session_id,
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "trace_id": trace_id,
                "status": "active",
                "state_version": 0,
                "metadata": dict(
                    metadata
                ),
                "started_at": utc_now(),
                "last_active_at": utc_now(),
                "ended_at": None,
            }

    async def get_session(
        self,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ):
        async with self._lock:
            session = self._sessions.get(
                session_id
            )

            if session is None:
                return None

            if (
                session["tenant_id"]
                != tenant_id
            ):
                return None

            return copy.deepcopy(
                session
            )

    async def close_session(
        self,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> None:
        async with self._lock:
            session = self._sessions.get(
                session_id
            )

            if session is None:
                return

            if (
                session["tenant_id"]
                != tenant_id
            ):
                raise PermissionError(
                    "cross_tenant_session_access"
                )

            session["status"] = "closed"
            session["ended_at"] = utc_now()
            session["last_active_at"] = utc_now()

    async def create_workflow(
        self,
        *,
        workflow_id: uuid.UUID,
        tenant_id: uuid.UUID,
        name: str,
        version: str,
        definition: dict,
        steps: list,
    ) -> None:
        async with self._lock:
            existing = self._workflows.get(
                workflow_id
            )

            if existing is not None:
                return

            self._workflows[
                workflow_id
            ] = {
                "workflow_id": workflow_id,
                "tenant_id": tenant_id,
                "name": name,
                "version": version,
                "definition": copy.deepcopy(
                    definition
                ),
                "steps": copy.deepcopy(
                    steps
                ),
            }

    async def create_workflow_run(
        self,
        *,
        run_id: uuid.UUID,
        workflow_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID | None,
        trace_id: str,
        input_hash: str | None,
    ) -> None:
        async with self._lock:
            self._workflow_runs[
                run_id
            ] = {
                "run_id": run_id,
                "workflow_id": workflow_id,
                "tenant_id": tenant_id,
                "session_id": session_id,
                "trace_id": trace_id,
                "status": "running",
                "input_hash": input_hash,
                "created_at": utc_now(),
            }


# ============================================================
# PostgreSQL store
# ============================================================

class PostgresRuntimeStore:
    """
    PostgreSQL-backed durable runtime store.
    """

    async def create_task(
        self,
        spec: TaskSpec,
    ) -> TaskRecord:
        metadata = build_task_metadata(
            spec
        )

        async with async_session() as session:
            row = RuntimeTask(
                task_id=spec.task_id,
                tenant_id=spec.tenant_id,
                agent_id=spec.agent_id,
                session_id=spec.session_id,
                workflow_run_id=spec.workflow_run_id,
                workflow_step_key=spec.workflow_step_key,
                trace_id=spec.effective_trace_id,
                kind=spec.kind,
                status=TaskStatus.CREATED.value,
                priority=spec.priority,
                payload_hash=spec.payload_hash,
                metadata_redacted=metadata,
                idempotency_key=spec.idempotency_key,
                attempt_count=0,
                max_attempts=spec.max_attempts,
                timeout_seconds=spec.timeout_seconds,
                available_at=utc_now(),
                latest_checkpoint_sequence=0,
            )

            session.add(row)

            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()

                if spec.idempotency_key:
                    existing = (
                        await session.execute(
                            select(
                                RuntimeTask
                            )
                            .where(
                                RuntimeTask.tenant_id
                                == spec.tenant_id
                            )
                            .where(
                                RuntimeTask.idempotency_key
                                == spec.idempotency_key
                            )
                        )
                    ).scalar_one_or_none()

                    if existing is not None:
                        return self._task_from_row(
                            existing,
                            spec=spec,
                        )

                raise

            return self._task_from_row(
                row,
                spec=spec,
            )

    async def get_task(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> TaskRecord | None:
        async with async_session() as session:
            row = (
                await session.execute(
                    select(RuntimeTask)
                    .where(
                        RuntimeTask.task_id
                        == task_id
                    )
                    .where(
                        RuntimeTask.tenant_id
                        == tenant_id
                    )
                )
            ).scalar_one_or_none()

            if row is None:
                return None

            return self._task_from_row(
                row
            )

    async def save_task(
        self,
        record: TaskRecord,
    ) -> TaskRecord:
        async with async_session() as session:
            row = (
                await session.execute(
                    select(RuntimeTask)
                    .where(
                        RuntimeTask.task_id
                        == record.task_id
                    )
                    .where(
                        RuntimeTask.tenant_id
                        == record.tenant_id
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()

            if row is None:
                raise KeyError(
                    "runtime_task_not_found"
                )

            row.status = record.status.value
            row.priority = record.spec.priority
            row.payload_hash = (
                record.spec.payload_hash
            )
            row.result_hash = record.result_hash
            row.metadata_redacted = (
                build_task_metadata(
                    record.spec
                )
            )
            row.attempt_count = (
                record.attempt_count
            )
            row.available_at = (
                record.available_at
            )
            row.started_at = (
                record.started_at
            )
            row.finished_at = (
                record.finished_at
            )
            row.last_error_code = (
                record.last_error_code
            )
            row.latest_checkpoint_sequence = (
                record.latest_checkpoint_sequence
            )

            await session.commit()

            return record

    async def list_ready_tasks(
        self,
        tenant_id: uuid.UUID,
        *,
        limit: int = 100,
    ) -> list[TaskRecord]:
        limit = max(
            1,
            min(limit, 1000),
        )

        async with async_session() as session:
            rows = (
                await session.execute(
                    select(RuntimeTask)
                    .where(
                        RuntimeTask.tenant_id
                        == tenant_id
                    )
                    .where(
                        RuntimeTask.status.in_(
                            [
                                TaskStatus.CREATED.value,
                                TaskStatus.QUEUED.value,
                                TaskStatus.RETRYING.value,
                            ]
                        )
                    )
                    .where(
                        RuntimeTask.available_at
                        <= utc_now()
                    )
                    .order_by(
                        RuntimeTask.priority.desc(),
                        RuntimeTask.available_at.asc(),
                    )
                    .limit(limit)
                )
            ).scalars().all()

            ready: list[
                TaskRecord
            ] = []

            for row in rows:
                dependency_statuses = (
                    await session.execute(
                        select(
                            RuntimeTask.status
                        )
                        .select_from(
                            RuntimeTaskDependency
                        )
                        .join(
                            RuntimeTask,
                            and_(
                                RuntimeTask.task_id
                                == (
                                    RuntimeTaskDependency
                                    .depends_on_task_id
                                ),
                                RuntimeTask.tenant_id
                                == (
                                    RuntimeTaskDependency
                                    .tenant_id
                                ),
                            ),
                        )
                        .where(
                            RuntimeTaskDependency.tenant_id
                            == tenant_id
                        )
                        .where(
                            RuntimeTaskDependency.task_id
                            == row.task_id
                        )
                    )
                ).all()

                if any(
                    status[0]
                    != TaskStatus.SUCCEEDED.value
                    for status
                    in dependency_statuses
                ):
                    continue

                ready.append(
                    self._task_from_row(
                        row
                    )
                )

            return ready

    async def list_tasks_with_failed_dependencies(
        self,
        tenant_id: uuid.UUID,
    ) -> list[TaskRecord]:
        """Return queued tasks with terminally failed prerequisites."""
        eligible = [
            TaskStatus.CREATED.value,
            TaskStatus.QUEUED.value,
            TaskStatus.RETRYING.value,
        ]
        terminal = [
            TaskStatus.FAILED.value,
            TaskStatus.CANCELLED.value,
            TaskStatus.BLOCKED.value,
        ]
        parent = aliased(RuntimeTask, name="dependency_parent")
        async with async_session() as session:
            rows = (
                await session.execute(
                    select(RuntimeTask)
                    .join(
                        RuntimeTaskDependency,
                        and_(
                            RuntimeTaskDependency.task_id == RuntimeTask.task_id,
                            RuntimeTaskDependency.tenant_id == RuntimeTask.tenant_id,
                        ),
                    )
                    .join(
                        parent,
                        and_(
                            RuntimeTaskDependency.depends_on_task_id == parent.task_id,
                            RuntimeTaskDependency.tenant_id == parent.tenant_id,
                        ),
                    )
                    .where(RuntimeTask.tenant_id == tenant_id)
                    .where(RuntimeTask.status.in_(eligible))
                    .where(parent.status.in_(terminal))
                    .distinct()
                )
            ).scalars().all()
            return [self._task_from_row(row) for row in rows]

    async def list_active_tenants(
        self,
    ) -> list[uuid.UUID]:
        async with async_session() as session:
            rows = (
                await session.execute(
                    select(
                        RuntimeTask.tenant_id
                    )
                    .where(
                        RuntimeTask.status.in_(
                            [
                                TaskStatus.CREATED.value,
                                TaskStatus.QUEUED.value,
                                TaskStatus.RETRYING.value,
                            ]
                        )
                    )
                    .distinct()
                )
            ).all()

            return sorted(
                {
                    row[0]
                    for row in rows
                },
                key=str,
            )

    async def add_dependency(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        depends_on_task_id: uuid.UUID,
    ) -> None:
        if task_id == depends_on_task_id:
            raise ValueError(
                "task_dependency_self_reference"
            )

        async with async_session() as session:
            task = (
                await session.execute(
                    select(RuntimeTask)
                    .where(
                        RuntimeTask.task_id
                        == task_id
                    )
                    .where(
                        RuntimeTask.tenant_id
                        == tenant_id
                    )
                )
            ).scalar_one_or_none()

            parent = (
                await session.execute(
                    select(RuntimeTask)
                    .where(
                        RuntimeTask.task_id
                        == depends_on_task_id
                    )
                    .where(
                        RuntimeTask.tenant_id
                        == tenant_id
                    )
                )
            ).scalar_one_or_none()

            if task is None or parent is None:
                raise KeyError(
                    "task_dependency_not_found"
                )

            session.add(
                RuntimeTaskDependency(
                    dependency_id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    task_id=task_id,
                    depends_on_task_id=(
                        depends_on_task_id
                    ),
                )
            )

            await session.commit()

    async def create_checkpoint(
        self,
        checkpoint,
    ) -> None:
        async with async_session() as session:
            row = RuntimeCheckpoint(
                checkpoint_id=(
                    checkpoint.checkpoint_id
                ),
                tenant_id=(
                    checkpoint.tenant_id
                ),
                task_id=checkpoint.task_id,
                sequence=checkpoint.sequence,
                state_hash=checkpoint.state_hash,
                metadata_redacted=(
                    checkpoint.metadata
                ),
                created_at=checkpoint.created_at,
            )

            session.add(row)

            await session.execute(
                update(RuntimeTask)
                .where(
                    RuntimeTask.task_id
                    == checkpoint.task_id
                )
                .where(
                    RuntimeTask.tenant_id
                    == checkpoint.tenant_id
                )
                .values(
                    latest_checkpoint_sequence=(
                        checkpoint.sequence
                    )
                )
            )

            await session.commit()

    async def latest_checkpoint(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ):
        async with async_session() as session:
            row = (
                await session.execute(
                    select(
                        RuntimeCheckpoint
                    )
                    .where(
                        RuntimeCheckpoint.tenant_id
                        == tenant_id
                    )
                    .where(
                        RuntimeCheckpoint.task_id
                        == task_id
                    )
                    .order_by(
                        RuntimeCheckpoint.sequence.desc()
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()

            if row is None:
                return None

            return self._checkpoint_from_row(
                row
            )

    async def list_checkpoints(
        self,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
        *,
        limit: int = 50,
    ):
        async with async_session() as session:
            rows = (
                await session.execute(
                    select(
                        RuntimeCheckpoint
                    )
                    .where(
                        RuntimeCheckpoint.tenant_id
                        == tenant_id
                    )
                    .where(
                        RuntimeCheckpoint.task_id
                        == task_id
                    )
                    .order_by(
                        RuntimeCheckpoint.sequence.desc()
                    )
                    .limit(
                        max(
                            1,
                            min(limit, 500),
                        )
                    )
                )
            ).scalars().all()

            return [
                self._checkpoint_from_row(
                    row
                )
                for row in rows
            ]

    async def append_runtime_event(
        self,
        *,
        tenant_id: uuid.UUID,
        trace_id: str,
        event_type: str,
        payload_hash: str | None,
        metadata: dict,
        task_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        workflow_run_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        async with async_session() as session:
            row = RuntimeEvent(
                event_id=uuid.uuid4(),
                tenant_id=tenant_id,
                task_id=task_id,
                session_id=session_id,
                workflow_run_id=workflow_run_id,
                trace_id=trace_id,
                event_type=event_type,
                event_version="1",
                correlation_id=correlation_id,
                payload_hash=payload_hash,
                metadata_redacted=dict(
                    metadata
                ),
                idempotency_key=idempotency_key,
                occurred_at=utc_now(),
            )

            session.add(row)

            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()

                if idempotency_key:
                    return

                raise

    async def create_session(
        self,
        *,
        session_id: uuid.UUID,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        trace_id: str,
        metadata: dict,
    ) -> None:
        async with async_session() as session:
            agent = (
                await session.execute(
                    select(Agent)
                    .where(
                        Agent.agent_id
                        == agent_id
                    )
                    .where(
                        Agent.tenant_id
                        == tenant_id
                    )
                )
            ).scalar_one_or_none()

            if agent is None:
                raise PermissionError(
                    "runtime_agent_not_found"
                )

            session.add(
                RuntimeSession(
                    session_id=session_id,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    status="active",
                    state_version=0,
                    metadata_redacted=dict(
                        metadata
                    ),
                    started_at=utc_now(),
                    last_active_at=utc_now(),
                )
            )

            await session.commit()

    async def get_session(
        self,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ):
        async with async_session() as session:
            return (
                await session.execute(
                    select(
                        RuntimeSession
                    )
                    .where(
                        RuntimeSession.session_id
                        == session_id
                    )
                    .where(
                        RuntimeSession.tenant_id
                        == tenant_id
                    )
                )
            ).scalar_one_or_none()

    async def close_session(
        self,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> None:
        async with async_session() as session:
            await session.execute(
                update(
                    RuntimeSession
                )
                .where(
                    RuntimeSession.session_id
                    == session_id
                )
                .where(
                    RuntimeSession.tenant_id
                    == tenant_id
                )
                .values(
                    status="closed",
                    ended_at=utc_now(),
                    last_active_at=utc_now(),
                )
            )

            await session.commit()

    async def create_workflow(
        self,
        *,
        workflow_id: uuid.UUID,
        tenant_id: uuid.UUID,
        name: str,
        version: str,
        definition: dict,
        steps: list,
    ) -> None:
        async with async_session() as session:
            workflow = WorkflowDefinition(
                workflow_id=workflow_id,
                tenant_id=tenant_id,
                name=name,
                version=version,
                active=False,
                definition_hash=canonical_hash(
                    definition
                ),
                definition_redacted=dict(
                    definition
                ),
                created_at=utc_now(),
                updated_at=utc_now(),
            )

            session.add(
                workflow
            )

            for ordinal, step in enumerate(
                steps
            ):
                session.add(
                    WorkflowStep(
                        step_id=uuid.uuid4(),
                        workflow_id=workflow_id,
                        step_key=step.key,
                        ordinal=ordinal,
                        task_kind=step.task_kind,
                        agent_id=step.agent_id,
                        config_hash=canonical_hash(
                            step.config
                        ),
                        config_redacted=dict(
                            step.config
                        ),
                        depends_on_step_keys=list(
                            step.depends_on
                        ),
                    )
                )

            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()

                existing = (
                    await session.execute(
                        select(
                            WorkflowDefinition
                        )
                        .where(
                            WorkflowDefinition.workflow_id
                            == workflow_id
                        )
                        .where(
                            WorkflowDefinition.tenant_id
                            == tenant_id
                        )
                    )
                ).scalar_one_or_none()

                if existing is None:
                    raise

    async def create_workflow_run(
        self,
        *,
        run_id: uuid.UUID,
        workflow_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID | None,
        trace_id: str,
        input_hash: str | None,
    ) -> None:
        async with async_session() as session:
            workflow = (
                await session.execute(
                    select(
                        WorkflowDefinition
                    )
                    .where(
                        WorkflowDefinition.workflow_id
                        == workflow_id
                    )
                    .where(
                        WorkflowDefinition.tenant_id
                        == tenant_id
                    )
                )
            ).scalar_one_or_none()

            if workflow is None:
                raise KeyError(
                    "workflow_not_found"
                )

            session.add(
                WorkflowRun(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    workflow_id=workflow_id,
                    session_id=session_id,
                    trace_id=trace_id,
                    status="running",
                    input_hash=input_hash,
                    output_hash=None,
                    metadata_redacted={},
                    started_at=utc_now(),
                    finished_at=None,
                )
            )

            await session.commit()

    @staticmethod
    def _task_from_row(
        row: RuntimeTask,
        *,
        spec: TaskSpec | None = None,
    ) -> TaskRecord:
        if spec is None:
            metadata = dict(
                row.metadata_redacted
                or {}
            )

            spec = TaskSpec(
                tenant_id=row.tenant_id,
                agent_id=row.agent_id,
                kind=row.kind,
                payload=None,
                metadata=metadata,
                session_id=row.session_id,
                workflow_run_id=row.workflow_run_id,
                workflow_step_key=(
                    row.workflow_step_key
                ),
                trace_id=row.trace_id,
                priority=row.priority,
                timeout_seconds=(
                    row.timeout_seconds
                ),
                max_attempts=(
                    row.max_attempts
                ),
                idempotency_key=(
                    row.idempotency_key
                ),
                task_id=row.task_id,
                payload_ref=metadata.get(
                    "payload_ref"
                ),
            )

        return TaskRecord(
            spec=spec,
            status=TaskStatus(
                row.status
            ),
            attempt_count=(
                row.attempt_count
            ),
            result=None,
            result_hash=row.result_hash,
            last_error_code=(
                row.last_error_code
            ),
            available_at=(
                row.available_at
            ),
            started_at=row.started_at,
            finished_at=row.finished_at,
            latest_checkpoint_sequence=(
                row.latest_checkpoint_sequence
            ),
        )

    @staticmethod
    def _checkpoint_from_row(
        row,
    ):
        from app.runtime.checkpoints import (
            Checkpoint,
        )

        return Checkpoint(
            checkpoint_id=(
                row.checkpoint_id
            ),
            tenant_id=row.tenant_id,
            task_id=row.task_id,
            sequence=row.sequence,
            state_hash=row.state_hash,
            metadata=dict(
                row.metadata_redacted
                or {}
            ),
            created_at=row.created_at,
        )


def default_runtime_store() -> RuntimeStore:
    """
    Select the default runtime persistence backend.
    """

    testing = (
        os.getenv(
            "AGENTSHIELD_TESTING"
        )
        == "1"
    )

    if testing:
        return InMemoryRuntimeStore()

    return PostgresRuntimeStore()