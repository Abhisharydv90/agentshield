"""
AURAGENT Runtime API.

Administrative and agent-facing runtime operations.

The API only creates/controls runtime work.
Actual execution still flows through the runtime execution boundary.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
)
from pydantic import BaseModel, Field

from app.runtime.bootstrap import (
    get_runtime_engine,
)
from app.runtime.tasks import (
    TaskSpec,
)
from app.security.capabilities import (
    Capability,
    require_capability,
)


router = APIRouter(
    prefix="/api/runtime",
    tags=["runtime"],
)


class TaskSubmitRequest(BaseModel):
    kind: str = Field(
        min_length=1,
        max_length=160,
    )

    payload: Any = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    priority: int = 0

    timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=86400,
    )

    max_attempts: int = Field(
        default=3,
        ge=1,
        le=100,
    )

    idempotency_key: str | None = Field(
        default=None,
        max_length=200,
    )


class TaskResponse(BaseModel):
    task_id: str
    tenant_id: str
    agent_id: str
    trace_id: str
    kind: str
    status: str
    priority: int
    attempt_count: int
    max_attempts: int
    timeout_seconds: int
    payload_hash: str
    result_hash: str | None = None
    last_error_code: str | None = None


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


def _require_owned_task(
    record,
    agent_id: uuid.UUID,
) -> None:
    """
    Require exact agent ownership for runtime task control.

    Tenant scoping alone is insufficient because one tenant can contain
    multiple autonomous agents with distinct authority boundaries.
    """

    if record is None or record.agent_id != agent_id:
        raise HTTPException(
            status_code=404,
            detail="runtime_task_not_found",
        )


def _session_agent_id(session: Any) -> uuid.UUID | None:
    value = (
        session.get("agent_id")
        if isinstance(session, dict)
        else getattr(session, "agent_id", None)
    )

    try:
        return uuid.UUID(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


def _require_owned_session(
    session: Any,
    agent_id: uuid.UUID,
) -> None:
    """
    Require exact agent ownership for runtime session control.

    Missing or malformed ownership metadata fails closed.
    """

    if session is None or _session_agent_id(session) != agent_id:
        raise HTTPException(
            status_code=404,
            detail="runtime_session_not_found",
        )


def _task_response(
    record,
) -> TaskResponse:
    return TaskResponse(
        task_id=str(
            record.task_id
        ),
        tenant_id=str(
            record.tenant_id
        ),
        agent_id=str(
            record.agent_id
        ),
        trace_id=record.trace_id,
        kind=record.spec.kind,
        status=record.status.value,
        priority=record.spec.priority,
        attempt_count=(
            record.attempt_count
        ),
        max_attempts=(
            record.spec.max_attempts
        ),
        timeout_seconds=(
            record.spec.timeout_seconds
        ),
        payload_hash=(
            record.spec.payload_hash
        ),
        result_hash=record.result_hash,
        last_error_code=(
            record.last_error_code
        ),
    )


@router.post(
    "/tasks",
    response_model=TaskResponse,
)
async def submit_task(
    request: Request,
    body: TaskSubmitRequest,
):
    tenant, agent = _require_agent(
        request
    )

    trace_id = getattr(
        request.state,
        "trace_id",
        None,
    )

    if not trace_id:
        trace_id = str(
            uuid.uuid4()
        )

    engine = await get_runtime_engine()

    spec = TaskSpec(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
        kind=body.kind,
        payload=body.payload,
        metadata=body.metadata,
        trace_id=trace_id,
        priority=body.priority,
        timeout_seconds=body.timeout_seconds,
        max_attempts=body.max_attempts,
        idempotency_key=(
            body.idempotency_key
        ),
    )

    try:
        record = await engine.submit_task(
            spec
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="runtime_task_submission_failed",
        ) from exc

    return _task_response(
        record
    )


@router.get(
    "/tasks/{task_id}",
    response_model=TaskResponse,
)
async def get_task(
    request: Request,
    task_id: uuid.UUID,
):
    tenant, agent = _require_agent(
        request
    )

    engine = await get_runtime_engine()

    record = await engine.store.get_task(
        tenant.tenant_id,
        task_id,
    )

    _require_owned_task(
        record,
        agent.agent_id,
    )

    return _task_response(
        record
    )


@router.post(
    "/tasks/{task_id}/cancel",
)
async def cancel_task(
    request: Request,
    task_id: uuid.UUID,
):
    tenant, agent = _require_agent(
        request
    )

    engine = await get_runtime_engine()

    record = await engine.store.get_task(
        tenant.tenant_id,
        task_id,
    )

    _require_owned_task(
        record,
        agent.agent_id,
    )

    cancelled = (
        await engine.cancel_task(
            tenant_id=tenant.tenant_id,
            task_id=task_id,
        )
    )

    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail="runtime_task_not_found_or_terminal",
        )

    return {
        "status": "cancelled",
        "task_id": str(task_id),
    }


@router.post(
    "/sessions",
)
async def create_session(
    request: Request,
):
    tenant, agent = _require_agent(
        request
    )

    trace_id = getattr(
        request.state,
        "trace_id",
        None,
    ) or str(
        uuid.uuid4()
    )

    engine = await get_runtime_engine()

    session = await engine.sessions.create(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
        trace_id=trace_id,
    )

    return {
        "session_id": str(
            session.session_id
        ),
        "tenant_id": str(
            session.tenant_id
        ),
        "agent_id": str(
            session.agent_id
        ),
        "trace_id": session.trace_id,
    }


@router.post(
    "/sessions/{session_id}/close",
)
async def close_session(
    request: Request,
    session_id: uuid.UUID,
):
    tenant, agent = _require_agent(
        request
    )

    engine = await get_runtime_engine()

    session = await engine.sessions.get(
        tenant_id=tenant.tenant_id,
        session_id=session_id,
    )

    _require_owned_session(
        session,
        agent.agent_id,
    )

    await engine.sessions.close(
        tenant_id=tenant.tenant_id,
        session_id=session_id,
    )

    return {
        "status": "closed",
        "session_id": str(
            session_id
        ),
    }
