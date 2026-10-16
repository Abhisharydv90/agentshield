"""
AURAGENT Workflow API.
"""

from __future__ import annotations

import json
import uuid

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
)
from pydantic import BaseModel, Field, model_validator

from app.runtime.bootstrap import (
    get_runtime_engine,
)
from app.runtime.workflows.engine import (
    WorkflowSpec,
    WorkflowStepSpec,
    WorkflowValidationError,
)
from app.security.capabilities import (
    Capability,
    require_capability,
)


router = APIRouter(
    prefix="/api/workflows",
    tags=["workflows"],
)


_MAX_WORKFLOW_INPUT_BYTES = 1024 * 1024
_MAX_WORKFLOW_STEP_CONFIG_BYTES = 128 * 1024


def _json_size(value) -> int:
    try:
        return len(
            json.dumps(
                value,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError, OverflowError):
        return _MAX_WORKFLOW_INPUT_BYTES + 1


class WorkflowStepRequest(BaseModel):
    key: str = Field(
        min_length=1,
        max_length=160,
    )

    task_kind: str = Field(
        min_length=1,
        max_length=120,
    )

    agent_id: uuid.UUID

    config: dict = Field(
        default_factory=dict,
        max_length=100,
    )

    depends_on: list[str] = Field(
        default_factory=list,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_config_budget(self):
        if _json_size(self.config) > _MAX_WORKFLOW_STEP_CONFIG_BYTES:
            raise ValueError("workflow_step_config_too_large")
        return self


class WorkflowSubmitRequest(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=160,
    )

    version: str = Field(
        min_length=1,
        max_length=64,
    )

    steps: list[
        WorkflowStepRequest
    ] = Field(
        min_length=1,
        max_length=200,
    )

    input_payload: object | None = None

    @model_validator(mode="after")
    def validate_input_budget(self):
        total = _json_size(self.input_payload)
        total += sum(_json_size(step.config) for step in self.steps)
        if total > _MAX_WORKFLOW_INPUT_BYTES:
            raise ValueError("workflow_input_too_large")
        return self


def _require_agent(
    request: Request,
):
    tenant = getattr(
        request.state,
        "tenant",
        None,
    )

    agent = getattr(
        request.state,
        "agent",
        None,
    )

    if tenant is None:
        raise HTTPException(
            status_code=401,
            detail="no_tenant",
        )

    if agent is None:
        raise HTTPException(
            status_code=403,
            detail="agent_identity_required",
        )

    if agent.status != "active":
        raise HTTPException(
            status_code=403,
            detail="agent_inactive",
        )

    require_capability(
        agent.scopes or [],
        Capability.AGENT_INVOKE,
    )

    return tenant, agent


@router.post(
    "",
)
async def submit_workflow(
    request: Request,
    body: WorkflowSubmitRequest,
):
    tenant, agent = _require_agent(
        request
    )

    if not body.steps:
        raise HTTPException(
            status_code=400,
            detail="workflow_steps_required",
        )

    for step in body.steps:
        if (
            step.agent_id
            != agent.agent_id
        ):
            raise HTTPException(
                status_code=403,
                detail="cross_agent_workflow_requires_delegation",
            )

    trace_id = getattr(
        request.state,
        "trace_id",
        None,
    ) or str(
        uuid.uuid4()
    )

    workflow_spec = WorkflowSpec(
        tenant_id=tenant.tenant_id,
        name=body.name,
        version=body.version,
        steps=tuple(
            WorkflowStepSpec(
                key=step.key,
                task_kind=step.task_kind,
                agent_id=step.agent_id,
                config=step.config,
                depends_on=tuple(
                    step.depends_on
                ),
            )
            for step in body.steps
        ),
    )

    engine = await get_runtime_engine()

    try:
        run = await engine.workflows.submit(
            spec=workflow_spec,
            trace_id=trace_id,
            input_payload=body.input_payload,
        )
    except WorkflowValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="workflow_submission_failed",
        ) from exc

    return {
        "run_id": str(
            run.run_id
        ),
        "workflow_id": str(
            run.workflow_id
        ),
        "tenant_id": str(
            run.tenant_id
        ),
        "trace_id": run.trace_id,
        "status": "submitted",
    }
