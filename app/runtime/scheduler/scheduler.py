"""
AURAGENT task scheduler.

Responsibilities:

- discover runnable tasks;
- enforce bounded concurrency;
- honor priorities;
- honor dependencies;
- invoke the runtime execution boundary;
- enforce task timeouts;
- integrate recovery;
- support cancellation.

The scheduler does NOT grant authority.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from app.runtime.lifecycle import LifecycleManager
from app.runtime.recovery import RecoveryManager
from app.runtime.tasks import (
    TaskRecord,
    TaskSpec,
    TaskStatus,
)


TaskExecutor = Callable[
    [TaskRecord],
    Any | Awaitable[Any],
]


class SchedulerStopped(RuntimeError):
    pass


class TaskScheduler:
    """
    Cooperative async runtime scheduler.

    Phase 13 can replace task discovery with a distributed queue while
    preserving this scheduling contract.
    """

    def __init__(
        self,
        store,
        *,
        executor: TaskExecutor,
        max_concurrency: int = 8,
        poll_interval_seconds: float = 0.5,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError(
                "max_concurrency_invalid"
            )

        if poll_interval_seconds <= 0:
            raise ValueError(
                "poll_interval_invalid"
            )

        if executor is None:
            raise ValueError(
                "scheduler_executor_required"
            )

        self.store = store
        self.executor = executor

        self.max_concurrency = (
            max_concurrency
        )

        self.poll_interval_seconds = (
            poll_interval_seconds
        )

        self._semaphore = asyncio.Semaphore(
            max_concurrency
        )

        self._running = False
        self._loop_task: (
            asyncio.Task | None
        ) = None

        self._active: dict[
            uuid.UUID,
            asyncio.Task,
        ] = {}

        self.recovery = RecoveryManager(
            store
        )

    # ========================================================
    # Lifecycle
    # ========================================================

    async def start(self) -> None:
        if self._running:
            return

        self._running = True

        self._loop_task = asyncio.create_task(
            self._run_loop(),
            name="auragent-runtime-scheduler",
        )

    async def stop(self) -> None:
        self._running = False

        loop_task = self._loop_task
        self._loop_task = None

        if loop_task is not None:
            loop_task.cancel()

            with contextlib.suppress(
                asyncio.CancelledError
            ):
                await loop_task

        active = list(
            self._active.values()
        )

        for task in active:
            task.cancel()

        if active:
            await asyncio.gather(
                *active,
                return_exceptions=True,
            )

        self._active.clear()

    # ========================================================
    # Submission
    # ========================================================

    async def submit(
        self,
        spec: TaskSpec,
        *,
        dependencies: list[
            uuid.UUID
        ] | None = None,
    ) -> TaskRecord:
        if not self._running:
            raise SchedulerStopped(
                "scheduler_not_running"
            )

        record = await self.store.create_task(
            spec
        )

        if record.status in {
            TaskStatus.CREATED,
            TaskStatus.RETRYING,
        }:
            LifecycleManager.queue(
                record
            )

            await self.store.save_task(
                record
            )

        for dependency_id in (
            dependencies or []
        ):
            await self.store.add_dependency(
                spec.tenant_id,
                spec.task_id,
                dependency_id,
            )

        await self.store.append_runtime_event(
            tenant_id=spec.tenant_id,
            trace_id=spec.effective_trace_id,
            event_type="task.submitted",
            payload_hash=spec.payload_hash,
            metadata={
                "task_id": str(
                    spec.task_id
                ),
                "kind": spec.kind,
                "priority": spec.priority,
            },
            task_id=spec.task_id,
            idempotency_key=(
                f"task-submitted:{spec.task_id}"
            ),
        )

        return record

    # ========================================================
    # Cancellation
    # ========================================================

    async def cancel(
        self,
        *,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> bool:
        record = await self.store.get_task(
            tenant_id,
            task_id,
        )

        if record is None:
            return False

        if record.is_terminal:
            return False

        current = self._active.get(
            task_id
        )

        if (
            current is not None
            and not current.done()
        ):
            current.cancel()

        LifecycleManager.cancel(
            record
        )

        await self.store.save_task(
            record
        )

        await self.store.append_runtime_event(
            tenant_id=tenant_id,
            trace_id=record.trace_id,
            event_type="task.cancelled",
            payload_hash=record.spec.payload_hash,
            metadata={
                "task_id": str(
                    task_id
                )
            },
            task_id=task_id,
        )

        return True

    # ========================================================
    # Scheduler loop
    # ========================================================

    async def _run_loop(self) -> None:
        while self._running:
            try:
                await self._resolve_failed_dependencies()
                candidates = (
                    await self._collect_candidates()
                )
            except Exception:
                await asyncio.sleep(
                    self.poll_interval_seconds
                )
                continue

            dispatched = False

            for record in candidates:
                if not self._running:
                    break

                if len(
                    self._active
                ) >= self.max_concurrency:
                    break

                if (
                    record.task_id
                    in self._active
                ):
                    continue

                worker = asyncio.create_task(
                    self._run_one(record),
                    name=(
                        "auragent-task-"
                        f"{record.task_id}"
                    ),
                )

                self._active[
                    record.task_id
                ] = worker

                worker.add_done_callback(
                    self._make_done_callback(
                        record.task_id
                    )
                )

                dispatched = True

            if not dispatched:
                await asyncio.sleep(
                    self.poll_interval_seconds
                )

    def _make_done_callback(
        self,
        task_id: uuid.UUID,
    ):
        def callback(
            _done: asyncio.Task,
        ) -> None:
            self._active.pop(
                task_id,
                None,
            )

        return callback

    async def _resolve_failed_dependencies(self) -> None:
        """Block queued tasks whose prerequisite can no longer succeed."""
        tenants = await self.store.list_active_tenants()
        for tenant_id in tenants:
            blocked = await self.store.list_tasks_with_failed_dependencies(
                tenant_id
            )
            for record in blocked:
                latest = await self.store.get_task(tenant_id, record.task_id)
                if latest is None or latest.status not in {
                    TaskStatus.CREATED,
                    TaskStatus.QUEUED,
                    TaskStatus.RETRYING,
                }:
                    continue
                LifecycleManager.block(
                    latest,
                    error_code="dependency_failed",
                )
                await self.store.save_task(latest)
                await self.store.append_runtime_event(
                    tenant_id=tenant_id,
                    trace_id=latest.trace_id,
                    event_type="task.blocked",
                    payload_hash=latest.spec.payload_hash,
                    metadata={
                        "task_id": str(latest.task_id),
                        "reason": "dependency_failed",
                    },
                    task_id=latest.task_id,
                )

    async def _collect_candidates(
        self,
    ) -> list[TaskRecord]:
        tenants = (
            await self.store.list_active_tenants()
        )

        candidates: list[
            TaskRecord
        ] = []

        for tenant_id in tenants:
            rows = (
                await self.store.list_ready_tasks(
                    tenant_id,
                    limit=max(
                        1,
                        self.max_concurrency * 2,
                    ),
                )
            )

            candidates.extend(
                rows
            )

        candidates.sort(
            key=lambda record: (
                -record.spec.priority,
                record.spec.created_at,
            )
        )

        return candidates

    # ========================================================
    # Execution
    # ========================================================

    async def _invoke_executor(
        self,
        record: TaskRecord,
    ) -> Any:
        """
        Correctly support:

            async def executor(...)
            def executor(...) -> value
            def executor(...) -> coroutine
        """

        callable_object = self.executor

        async_call = (
            inspect.iscoroutinefunction(
                callable_object
            )
            or inspect.iscoroutinefunction(
                getattr(
                    callable_object,
                    "__call__",
                    None,
                )
            )
        )

        if async_call:
            result = callable_object(
                record
            )

            if inspect.isawaitable(
                result
            ):
                return await result

            return result

        result = await asyncio.to_thread(
            callable_object,
            record,
        )

        if inspect.isawaitable(
            result
        ):
            return await result

        return result

    async def _run_one(
        self,
        record: TaskRecord,
    ) -> None:
        async with self._semaphore:
            current = await self.store.get_task(
                record.tenant_id,
                record.task_id,
            )

            if current is None:
                return

            if current.status not in {
                TaskStatus.CREATED,
                TaskStatus.QUEUED,
                TaskStatus.RETRYING,
            }:
                return

            try:
                LifecycleManager.start(
                    current
                )

                await self.store.save_task(
                    current
                )

                await self.store.append_runtime_event(
                    tenant_id=current.tenant_id,
                    trace_id=current.trace_id,
                    event_type="task.started",
                    payload_hash=(
                        current.spec.payload_hash
                    ),
                    metadata={
                        "task_id": str(
                            current.task_id
                        ),
                        "attempt_count": (
                            current.attempt_count
                        ),
                    },
                    task_id=current.task_id,
                )

                result = await asyncio.wait_for(
                    self._invoke_executor(
                        current
                    ),
                    timeout=(
                        current.spec.timeout_seconds
                    ),
                )

                LifecycleManager.succeed(
                    current,
                    result,
                )

                await self.store.save_task(
                    current
                )

                await self.store.append_runtime_event(
                    tenant_id=current.tenant_id,
                    trace_id=current.trace_id,
                    event_type="task.succeeded",
                    payload_hash=current.result_hash,
                    metadata={
                        "task_id": str(
                            current.task_id
                        ),
                        "attempt_count": (
                            current.attempt_count
                        ),
                    },
                    task_id=current.task_id,
                )

            except asyncio.TimeoutError:
                await self.recovery.handle_failure(
                    current,
                    error_code="task_timeout",
                )

            except asyncio.CancelledError:
                with contextlib.suppress(
                    Exception
                ):
                    latest = await self.store.get_task(
                        current.tenant_id,
                        current.task_id,
                    )

                    if (
                        latest is not None
                        and not latest.is_terminal
                    ):
                        LifecycleManager.cancel(
                            latest
                        )

                        await self.store.save_task(
                            latest
                        )

                raise

            except Exception as exc:
                error_code = (
                    type(exc).__name__
                    .lower()
                )

                await self.recovery.handle_failure(
                    current,
                    error_code=error_code,
                )