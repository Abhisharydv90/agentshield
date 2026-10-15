"""
AURAGENT workflow orchestration engine.

Workflow properties:

- deterministic validation;
- DAG cycle detection;
- durable definition registration;
- durable run registration;
- task dependency creation;
- tenant isolation;
- trace propagation.

Workflow structure is never treated as authorization.
Every task still travels through the normal execution/security
boundaries.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from app.runtime.tasks import (
    TaskSpec,
    canonical_hash,
)


class WorkflowValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WorkflowStepSpec:
    key: str
    task_kind: str
    agent_id: uuid.UUID
    config: dict[str, Any] = field(
        default_factory=dict
    )
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WorkflowSpec:
    tenant_id: uuid.UUID
    name: str
    version: str
    steps: tuple[
        WorkflowStepSpec,
        ...,
    ]


@dataclass(frozen=True, slots=True)
class WorkflowPlan:
    workflow_id: uuid.UUID
    ordered_steps: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WorkflowRunHandle:
    run_id: uuid.UUID
    workflow_id: uuid.UUID
    tenant_id: uuid.UUID
    trace_id: str


class WorkflowEngine:
    """
    AURAGENT workflow engine.
    """

    def __init__(
        self,
        store,
        scheduler,
    ) -> None:
        self.store = store
        self.scheduler = scheduler

    # ========================================================
    # Validation
    # ========================================================

    def validate(
        self,
        spec: WorkflowSpec,
    ) -> WorkflowPlan:
        if not spec.name.strip():
            raise WorkflowValidationError(
                "workflow_name_required"
            )

        if not spec.version.strip():
            raise WorkflowValidationError(
                "workflow_version_required"
            )

        if not spec.steps:
            raise WorkflowValidationError(
                "workflow_steps_required"
            )

        steps = {
            step.key: step
            for step in spec.steps
        }

        if len(steps) != len(
            spec.steps
        ):
            raise WorkflowValidationError(
                "duplicate_workflow_step"
            )

        for step in spec.steps:
            if not step.key.strip():
                raise WorkflowValidationError(
                    "workflow_step_key_required"
                )

            if not step.task_kind.strip():
                raise WorkflowValidationError(
                    "workflow_step_task_kind_required"
                )

            for dependency in (
                step.depends_on
            ):
                if dependency not in steps:
                    raise WorkflowValidationError(
                        (
                            "unknown_workflow_dependency:"
                            f"{dependency}"
                        )
                    )

                if dependency == step.key:
                    raise WorkflowValidationError(
                        "workflow_self_dependency"
                    )

        ordered = self._topological_order(
            steps
        )

        workflow_id = uuid.uuid5(
            uuid.NAMESPACE_URL,
            (
                "auragent:"
                f"{spec.tenant_id}:"
                f"{spec.name}:"
                f"{spec.version}"
            ),
        )

        return WorkflowPlan(
            workflow_id=workflow_id,
            ordered_steps=tuple(
                ordered
            ),
        )

    # ========================================================
    # Submit
    # ========================================================

    async def submit(
        self,
        *,
        spec: WorkflowSpec,
        trace_id: str,
        session_id: uuid.UUID | None = None,
        input_payload: Any = None,
    ) -> WorkflowRunHandle:
        plan = self.validate(
            spec
        )

        if not trace_id:
            raise WorkflowValidationError(
                "workflow_trace_required"
            )

        if len(trace_id) > 128:
            raise WorkflowValidationError(
                "workflow_trace_too_long"
            )

        definition = {
            "name": spec.name,
            "version": spec.version,
            "steps": [
                {
                    "key": step.key,
                    "task_kind": step.task_kind,
                    "agent_id": str(
                        step.agent_id
                    ),
                    "config": step.config,
                    "depends_on": list(
                        step.depends_on
                    ),
                }
                for step in spec.steps
            ],
        }

        await self.store.create_workflow(
            workflow_id=plan.workflow_id,
            tenant_id=spec.tenant_id,
            name=spec.name,
            version=spec.version,
            definition=definition,
            steps=list(spec.steps),
        )

        run_id = uuid.uuid4()

        input_hash = (
            canonical_hash(
                input_payload
            )
            if input_payload is not None
            else None
        )

        await self.store.create_workflow_run(
            run_id=run_id,
            workflow_id=plan.workflow_id,
            tenant_id=spec.tenant_id,
            session_id=session_id,
            trace_id=trace_id,
            input_hash=input_hash,
        )

        created_tasks: dict[
            str,
            uuid.UUID,
        ] = {}

        for step_key in (
            plan.ordered_steps
        ):
            step = next(
                item
                for item in spec.steps
                if item.key == step_key
            )

            task_id = uuid.uuid4()

            dependencies = [
                created_tasks[
                    dependency
                ]
                for dependency
                in step.depends_on
            ]

            task_spec = TaskSpec(
                tenant_id=spec.tenant_id,
                agent_id=step.agent_id,
                kind=step.task_kind,
                payload=step.config,
                metadata={
                    "workflow_id": str(
                        plan.workflow_id
                    ),
                    "workflow_run_id": str(
                        run_id
                    ),
                    "workflow_step": step.key,
                },
                session_id=session_id,
                workflow_run_id=run_id,
                workflow_step_key=step.key,
                trace_id=trace_id,
                task_id=task_id,
            )

            await self.scheduler.submit(
                task_spec,
                dependencies=dependencies,
            )

            created_tasks[
                step.key
            ] = task_id

        await self.store.append_runtime_event(
            tenant_id=spec.tenant_id,
            trace_id=trace_id,
            event_type="workflow.submitted",
            payload_hash=input_hash,
            metadata={
                "workflow_id": str(
                    plan.workflow_id
                ),
                "workflow_run_id": str(
                    run_id
                ),
                "workflow_name": spec.name,
                "workflow_version": spec.version,
                "step_count": len(
                    spec.steps
                ),
            },
            session_id=session_id,
            workflow_run_id=run_id,
            idempotency_key=(
                f"workflow-submitted:{run_id}"
            ),
        )

        return WorkflowRunHandle(
            run_id=run_id,
            workflow_id=plan.workflow_id,
            tenant_id=spec.tenant_id,
            trace_id=trace_id,
        )

    # ========================================================
    # DAG algorithm
    # ========================================================

    @staticmethod
    def _topological_order(
        steps: dict[
            str,
            WorkflowStepSpec,
        ],
    ) -> list[str]:
        state: dict[
            str,
            int,
        ] = {
            key: 0
            for key in steps
        }

        ordered: list[str] = []

        def visit(
            key: str,
        ) -> None:
            current = state[key]

            if current == 1:
                raise WorkflowValidationError(
                    "workflow_cycle_detected"
                )

            if current == 2:
                return

            state[key] = 1

            for dependency in (
                steps[
                    key
                ].depends_on
            ):
                visit(
                    dependency
                )

            state[key] = 2
            ordered.append(
                key
            )

        for key in steps:
            visit(key)

        return ordered