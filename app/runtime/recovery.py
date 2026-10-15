"""
AURAGENT runtime recovery.

Recovery is responsible for deciding whether a failed task should:
- retry,
- fail permanently,
- or require operator intervention.

It never bypasses authorization.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.runtime.lifecycle import LifecycleManager
from app.runtime.tasks import TaskRecord, TaskStatus


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RecoveryManager:
    """
    Crash/retry recovery policy.

    Exponential retry delay is bounded to prevent runaway retries.
    """

    def __init__(
        self,
        store,
        *,
        base_delay_seconds: float = 2.0,
        max_delay_seconds: float = 300.0,
    ) -> None:
        self.store = store
        self.base_delay_seconds = base_delay_seconds
        self.max_delay_seconds = max_delay_seconds

    def retry_delay(
        self,
        attempt_count: int,
    ) -> float:
        attempt = max(
            1,
            attempt_count,
        )

        delay = (
            self.base_delay_seconds
            * (2 ** (attempt - 1))
        )

        return min(
            delay,
            self.max_delay_seconds,
        )

    async def handle_failure(
        self,
        record: TaskRecord,
        *,
        error_code: str,
    ) -> TaskRecord:
        if record.status != TaskStatus.RUNNING:
            raise ValueError(
                "recovery_requires_running_task"
            )

        if (
            record.attempt_count
            < record.spec.max_attempts
        ):
            LifecycleManager.retry(
                record,
                error_code,
            )

            record.available_at = (
                utc_now()
                + timedelta(
                    seconds=self.retry_delay(
                        record.attempt_count
                    )
                )
            )

            await self.store.save_task(
                record
            )

            await self.store.append_runtime_event(
                tenant_id=record.tenant_id,
                trace_id=record.trace_id,
                event_type="task.retry_scheduled",
                payload_hash=record.spec.payload_hash,
                metadata={
                    "task_id": str(
                        record.task_id
                    ),
                    "attempt_count": record.attempt_count,
                    "error_code": error_code,
                },
                task_id=record.task_id,
            )

            return record

        LifecycleManager.fail(
            record,
            error_code,
        )

        await self.store.save_task(
            record
        )

        await self.store.append_runtime_event(
            tenant_id=record.tenant_id,
            trace_id=record.trace_id,
            event_type="task.failed",
            payload_hash=record.spec.payload_hash,
            metadata={
                "task_id": str(record.task_id),
                "attempt_count": record.attempt_count,
                "error_code": error_code,
            },
            task_id=record.task_id,
        )

        return record

    async def recover_stale_task(
        self,
        record: TaskRecord,
    ) -> TaskRecord:
        """
        Convert a task discovered RUNNING after process failure into
        RETRYING or FAILED according to the normal retry contract.
        """

        if record.status != TaskStatus.RUNNING:
            return record

        return await self.handle_failure(
            record,
            error_code="runtime_worker_lost",
        )