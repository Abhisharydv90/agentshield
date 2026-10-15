"""
AURAGENT task execution boundary.

The Runtime Scheduler decides WHEN a task may run.

This module defines WHO/WHAT actually executes it.

Important architectural rule:

    Runtime
        !=
    Authority

The executor is intentionally an integration seam for later phases:

Phase 4  -> Trust / authorization
Phase 5  -> Tool Fabric
Phase 7  -> Isolation
Phase 8  -> Evidence

A task reaching the executor does not itself grant permission to
perform arbitrary operations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.runtime.tasks import TaskRecord


class RuntimeExecutionError(RuntimeError):
    """Base class for runtime execution failures."""


class ExecutorNotConfigured(RuntimeExecutionError):
    """
    Raised when the runtime has not yet been connected to an actual
    execution provider.
    """


class TaskExecutorProtocol(ABC):
    """
    Abstract execution boundary.

    Implementations may eventually route to:
    - agent runtimes,
    - Tool Fabric,
    - isolated workers,
    - MCP,
    - A2A,
    - model providers,
    - workflow workers.
    """

    @abstractmethod
    async def execute(
        self,
        task: TaskRecord,
    ) -> Any:
        """
        Execute one already-scheduled task.

        Authorization must be performed by the appropriate security
        boundary before irreversible actions occur.
        """
        raise NotImplementedError


class UnconfiguredExecutor(TaskExecutorProtocol):
    """
    Safe default executor.

    It never silently executes arbitrary work.
    """

    async def execute(
        self,
        task: TaskRecord,
    ) -> Any:
        raise ExecutorNotConfigured(
            "runtime_executor_not_configured"
        )


class CallableExecutor(TaskExecutorProtocol):
    """
    Adapter for a normal Python callable.

    This allows the runtime to remain independent from whatever
    execution implementation a later phase supplies.
    """

    def __init__(
        self,
        callback,
    ) -> None:
        if callback is None:
            raise ValueError(
                "executor_callback_required"
            )

        self.callback = callback

    async def execute(
        self,
        task: TaskRecord,
    ) -> Any:
        result = self.callback(task)

        if hasattr(result, "__await__"):
            return await result

        return result