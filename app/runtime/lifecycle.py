"""
AURAGENT runtime lifecycle state machine.

The lifecycle manager is deliberately deterministic.

No model/LLM/judge may directly mutate task state.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.runtime.tasks import (
    TaskRecord,
    TaskStatus,
)


class InvalidTaskTransition(RuntimeError):
    """Raised when a task transition is not permitted."""


_ALLOWED_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.CREATED: {
        TaskStatus.QUEUED,
        TaskStatus.CANCELLED,
        TaskStatus.BLOCKED,
    },
    TaskStatus.QUEUED: {
        TaskStatus.RUNNING,
        TaskStatus.CANCELLED,
        TaskStatus.BLOCKED,
    },
    TaskStatus.RUNNING: {
        TaskStatus.SUCCEEDED,
        TaskStatus.FAILED,
        TaskStatus.RETRYING,
        TaskStatus.CANCELLED,
    },
    TaskStatus.RETRYING: {
        TaskStatus.QUEUED,
        TaskStatus.RUNNING,
        TaskStatus.CANCELLED,
        TaskStatus.BLOCKED,
    },
    TaskStatus.BLOCKED: {
        TaskStatus.QUEUED,
        TaskStatus.CANCELLED,
    },
    TaskStatus.SUCCEEDED: set(),
    TaskStatus.FAILED: set(),
    TaskStatus.CANCELLED: set(),
}


class LifecycleManager:
    """
    Authoritative task lifecycle transition service.
    """

    @staticmethod
    def can_transition(
        current: TaskStatus,
        target: TaskStatus,
    ) -> bool:
        return target in _ALLOWED_TRANSITIONS.get(
            current,
            set(),
        )

    @staticmethod
    def transition(
        record: TaskRecord,
        target: TaskStatus,
        *,
        error_code: str | None = None,
    ) -> TaskRecord:
        if record.status == target:
            return record

        if not LifecycleManager.can_transition(
            record.status,
            target,
        ):
            raise InvalidTaskTransition(
                f"{record.status.value}->{target.value}"
            )

        now = datetime.now(timezone.utc)

        record.status = target
        record.version += 1

        if target == TaskStatus.RUNNING:
            if record.started_at is None:
                record.started_at = now

            record.attempt_count += 1

        if target == TaskStatus.RETRYING:
            record.last_error_code = error_code

        if target == TaskStatus.FAILED:
            record.last_error_code = error_code
            record.finished_at = now

        if target == TaskStatus.SUCCEEDED:
            record.last_error_code = None
            record.finished_at = now

        if target == TaskStatus.CANCELLED:
            record.finished_at = now

        return record

    @staticmethod
    def queue(record: TaskRecord) -> TaskRecord:
        return LifecycleManager.transition(
            record,
            TaskStatus.QUEUED,
        )

    @staticmethod
    def start(record: TaskRecord) -> TaskRecord:
        return LifecycleManager.transition(
            record,
            TaskStatus.RUNNING,
        )

    @staticmethod
    def succeed(
        record: TaskRecord,
        result: object,
    ) -> TaskRecord:
        from app.runtime.tasks import canonical_hash

        record.result = result
        record.result_hash = canonical_hash(result)

        return LifecycleManager.transition(
            record,
            TaskStatus.SUCCEEDED,
        )

    @staticmethod
    def fail(
        record: TaskRecord,
        error_code: str,
    ) -> TaskRecord:
        return LifecycleManager.transition(
            record,
            TaskStatus.FAILED,
            error_code=error_code,
        )

    @staticmethod
    def retry(
        record: TaskRecord,
        error_code: str,
    ) -> TaskRecord:
        return LifecycleManager.transition(
            record,
            TaskStatus.RETRYING,
            error_code=error_code,
        )

    @staticmethod
    def cancel(record: TaskRecord) -> TaskRecord:
        return LifecycleManager.transition(
            record,
            TaskStatus.CANCELLED,
        )

    @staticmethod
    def block(
        record: TaskRecord,
        error_code: str = "dependency_failed",
    ) -> TaskRecord:
        LifecycleManager.transition(
            record,
            TaskStatus.BLOCKED,
        )
        record.last_error_code = error_code
        return record