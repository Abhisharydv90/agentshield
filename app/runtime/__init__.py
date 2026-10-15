"""
AURAGENT Runtime & Orchestration.

The runtime is the central execution heartbeat of AURAGENT.

Responsibilities:
- task lifecycle;
- scheduling;
- durable execution;
- sessions;
- state;
- checkpoints;
- recovery;
- workflows;
- multi-agent coordination.

The runtime does NOT itself grant capabilities.

Security authority remains in the Trust/Security Kernel.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.runtime.checkpoints import (
    CheckpointManager,
)
from app.runtime.coordination import (
    AgentCoordinator,
)
from app.runtime.durable import (
    RuntimeStore,
    default_runtime_store,
)
from app.runtime.recovery import (
    RecoveryManager,
)
from app.runtime.scheduler.scheduler import (
    TaskExecutor,
    TaskScheduler,
)
from app.runtime.sessions.manager import (
    SessionManager,
)
from app.runtime.state import (
    StateManager,
)
from app.runtime.workflows.engine import (
    WorkflowEngine,
)


@dataclass(slots=True)
class RuntimeEngine:
    """
    Complete AURAGENT runtime composition root.
    """

    store: RuntimeStore
    scheduler: TaskScheduler
    sessions: SessionManager
    checkpoints: CheckpointManager
    state: StateManager
    recovery: RecoveryManager
    coordination: AgentCoordinator
    workflows: WorkflowEngine

    @classmethod
    def create(
        cls,
        *,
        executor: TaskExecutor,
        store: RuntimeStore | None = None,
        max_concurrency: int = 8,
        poll_interval_seconds: float = 0.5,
    ) -> "RuntimeEngine":
        selected_store = (
            store
            if store is not None
            else default_runtime_store()
        )

        scheduler = TaskScheduler(
            selected_store,
            executor=executor,
            max_concurrency=max_concurrency,
            poll_interval_seconds=(
                poll_interval_seconds
            ),
        )

        sessions = SessionManager(
            selected_store
        )

        checkpoints = CheckpointManager(
            selected_store
        )

        recovery = RecoveryManager(
            selected_store
        )

        coordination = AgentCoordinator()

        workflows = WorkflowEngine(
            selected_store,
            scheduler,
        )

        return cls(
            store=selected_store,
            scheduler=scheduler,
            sessions=sessions,
            checkpoints=checkpoints,
            state=StateManager(),
            recovery=recovery,
            coordination=coordination,
            workflows=workflows,
        )

    async def start(self) -> None:
        await self.scheduler.start()

    async def stop(self) -> None:
        await self.scheduler.stop()

    async def submit_task(
        self,
        spec,
        *,
        dependencies=None,
    ):
        return await self.scheduler.submit(
            spec,
            dependencies=dependencies,
        )

    async def cancel_task(
        self,
        *,
        tenant_id: uuid.UUID,
        task_id: uuid.UUID,
    ) -> bool:
        return await self.scheduler.cancel(
            tenant_id=tenant_id,
            task_id=task_id,
        )


__all__ = [
    "RuntimeEngine",
    "RuntimeStore",
    "TaskExecutor",
    "TaskScheduler",
    "SessionManager",
    "CheckpointManager",
    "StateManager",
    "RecoveryManager",
    "AgentCoordinator",
    "WorkflowEngine",
]