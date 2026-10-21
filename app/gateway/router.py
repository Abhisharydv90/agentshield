"""
AURAGENT unified Gateway.

Entry point:

    /v1/gateway/dispatch

Specialized model endpoint:

    /v1/gateway/models/{route_name}/chat/completions

The Gateway provides:

- authentication context enforcement;
- capability enforcement;
- request validation;
- tenant isolation;
- quota enforcement;
- model routing;
- agent routing;
- MCP routing;
- A2A routing;
- observability.

Model requests are deliberately passed into the existing AgentShield
security proxy so the Gateway does not create a second, divergent
security pipeline.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
)
from fastapi.responses import (
    JSONResponse,
    Response,
    StreamingResponse,
)

from app.db.models import RequestLog
from app.db.session import async_session
from app.gateway.observability import (
    GatewayObservation,
    gateway_metrics,
)
from app.gateway.quotas import (
    quota_manager,
)
from app.gateway.routing.a2a import (
    A2ARouteError,
    a2a_router,
)
from app.gateway.routing.agent import (
    AgentRouteError,
    AgentRouter,
)
from app.gateway.routing.mcp import (
    MCPRouteError,
    mcp_router,
)
from app.gateway.routing.model import (
    ModelRouteError,
    get_model_router,
)
from app.gateway.validation import (
    GatewayRequest,
    GatewayTargetKind,
)
from app.proxy.router import (
    chat_completions,
)
from app.security.capabilities import (
    Capability,
    require_capability,
)


router = APIRouter(
    prefix="/v1/gateway",
    tags=["gateway"],
)


_agent_router = AgentRouter()


# ============================================================
# Authentication
# ============================================================

def _principal(
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


# ============================================================
# Internal model request adapter
# ============================================================

def _build_internal_proxy_request(
    request: Request,
    *,
    payload: Any,
    route_name: str,
) -> Request:
    """
    Create an internal Request carrying ONLY the validated model
    payload.

    The existing proxy security pipeline receives this request after
    the Gateway has already authenticated and quota-checked it.
    """

    body = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    sent = False

    async def receive() -> dict:
        nonlocal sent

        if sent:
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        sent = True

        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    scope = dict(
        request.scope
    )

    state = dict(
        scope.get(
            "state",
            {},
        )
    )

    state[
        "tenant"
    ] = getattr(
        request.state,
        "tenant",
        None,
    )

    state[
        "agent"
    ] = getattr(
        request.state,
        "agent",
        None,
    )

    state[
        "trace_id"
    ] = getattr(
        request.state,
        "trace_id",
        None,
    )

    state[
        "gateway_model_route"
    ] = route_name

    scope["state"] = state

    return Request(
        scope,
        receive,
    )


# ============================================================
# Observation helpers
# ============================================================

async def _observe(
    *,
    tenant_id,
    agent_id,
    target_kind: str,
    target_name: str,
    status_code: int,
    started_ms: float,
    outcome: str,
    provider_model: str | None = None,
) -> None:
    latency_ms = (
        time.perf_counter() * 1000
        - started_ms
    )

    await gateway_metrics.observe(
        GatewayObservation(
            target_kind=target_kind,
            target_name=target_name,
            status_code=status_code,
            latency_ms=latency_ms,
            outcome=outcome,
        )
    )

    request_id = str(
        uuid.uuid4()
    )

    try:
        async with async_session() as session:
            session.add(
                RequestLog(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    agent_identity=str(
                        agent_id
                    ),
                    provider_model=(
                        provider_model
                        or target_name
                    ),
                    total_tokens=0,
                    latency_ms=int(
                        max(
                            0,
                            latency_ms,
                        )
                    ),
                    outcome=outcome,
                )
            )

            await session.commit()
    except Exception:
        # Observability must not become an accidental data-plane outage.
        pass


# ============================================================
# Quota wrapping
# ============================================================

def _wrap_streaming_release(
    response: StreamingResponse,
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    observation: dict,
) -> StreamingResponse:
    original_iterator = response.body_iterator

    async def wrapped_iterator():
        started_ms = observation[
            "started_ms"
        ]

        try:
            async for chunk in original_iterator:
                yield chunk
        finally:
            await quota_manager.release(
                tenant_id=tenant_id,
                agent_id=agent_id,
            )

            await _observe(
                tenant_id=tenant_id,
                agent_id=agent_id,
                target_kind=observation[
                    "target_kind"
                ],
                target_name=observation[
                    "target_name"
                ],
                status_code=(
                    getattr(
                        response,
                        "status_code",
                        200,
                    )
                ),
                started_ms=started_ms,
                outcome=(
                    "allowed"
                    if getattr(
                        response,
                        "status_code",
                        200,
                    ) < 400
                    else "error"
                ),
            )

    response.body_iterator = (
        wrapped_iterator()
    )

    return response


# ============================================================
# Unified dispatch
# ============================================================

@router.post(
    "/dispatch",
)
async def dispatch(
    request: Request,
    body: GatewayRequest,
):
    tenant, agent = _principal(
        request
    )

    quota = await quota_manager.acquire(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
    )

    if not quota.allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "gateway_quota_exceeded",
                "reason": quota.reason,
            },
            headers={
                "Retry-After": str(
                    quota.retry_after_seconds
                ),
            },
        )

    started_ms = (
        time.perf_counter() * 1000
    )

    kind = body.target.kind
    name = body.target.name

    observation = {
        "target_kind": kind.value,
        "target_name": name,
        "started_ms": started_ms,
    }

    try:
        # ----------------------------------------------------
        # MODEL
        # ----------------------------------------------------
        if kind == GatewayTargetKind.MODEL:
            get_model_router().resolve(
                name
            )

            internal_request = (
                _build_internal_proxy_request(
                    request,
                    payload=body.payload,
                    route_name=name,
                )
            )

            response = await chat_completions(
                internal_request
            )

            if isinstance(
                response,
                StreamingResponse,
            ):
                return _wrap_streaming_release(
                    response,
                    tenant_id=tenant.tenant_id,
                    agent_id=agent.agent_id,
                    observation=observation,
                )

            status_code = getattr(
                response,
                "status_code",
                200,
            )

            await quota_manager.release(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
            )

            await _observe(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
                target_kind=kind.value,
                target_name=name,
                status_code=status_code,
                started_ms=started_ms,
                outcome=(
                    "allowed"
                    if status_code < 400
                    else "error"
                ),
            )

            return response

        # ----------------------------------------------------
        # AGENT
        # ----------------------------------------------------
        if kind == GatewayTargetKind.AGENT:
            result = await _agent_router.dispatch(
                tenant_id=tenant.tenant_id,
                caller_agent_id=agent.agent_id,
                target_name=name,
                trace_id=(
                    getattr(
                        request.state,
                        "trace_id",
                        None,
                    )
                    or str(
                        uuid.uuid4()
                    )
                ),
                payload=body.payload,
                metadata=body.metadata,
            )

            await quota_manager.release(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
            )

            await _observe(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
                target_kind=kind.value,
                target_name=name,
                status_code=202,
                started_ms=started_ms,
                outcome="accepted",
            )

            return JSONResponse(
                status_code=202,
                content=result,
            )

        # ----------------------------------------------------
        # MCP
        # ----------------------------------------------------
        if kind == GatewayTargetKind.MCP:
            trace_id = (
                getattr(
                    request.state,
                    "trace_id",
                    None,
                )
                or str(
                    uuid.uuid4()
                )
            )

            result = await mcp_router.dispatch(
                route_name=name,
                trace_id=trace_id,
                tenant_id=str(
                    tenant.tenant_id
                ),
                agent_id=str(
                    agent.agent_id
                ),
                agent_scopes=agent.scopes or [],
                payload=body.payload,
            )

            await quota_manager.release(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
            )

            status_code = int(
                result.get(
                    "status_code",
                    200,
                )
            )

            await _observe(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
                target_kind=kind.value,
                target_name=name,
                status_code=status_code,
                started_ms=started_ms,
                outcome=(
                    "allowed"
                    if status_code < 400
                    else "error"
                ),
            )

            return JSONResponse(
                status_code=(
                    200
                    if status_code < 400
                    else 502
                ),
                content=result,
            )

        # ----------------------------------------------------
        # A2A
        # ----------------------------------------------------
        if kind == GatewayTargetKind.A2A:
            trace_id = (
                getattr(
                    request.state,
                    "trace_id",
                    None,
                )
                or str(
                    uuid.uuid4()
                )
            )

            result = await a2a_router.dispatch(
                route_name=name,
                tenant_id=str(
                    tenant.tenant_id
                ),
                agent_id=str(
                    agent.agent_id
                ),
                trace_id=trace_id,
                agent_scopes=agent.scopes or [],
                payload=body.payload,
            )

            await quota_manager.release(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
            )

            status_code = int(
                result.get(
                    "status_code",
                    200,
                )
            )

            await _observe(
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
                target_kind=kind.value,
                target_name=name,
                status_code=status_code,
                started_ms=started_ms,
                outcome=(
                    "allowed"
                    if status_code < 400
                    else "error"
                ),
            )

            return JSONResponse(
                status_code=(
                    200
                    if status_code < 400
                    else 502
                ),
                content=result,
            )

        raise HTTPException(
            status_code=400,
            detail="unsupported_gateway_target",
        )

    except (
        ModelRouteError,
        AgentRouteError,
        MCPRouteError,
        A2ARouteError,
    ) as exc:
        await quota_manager.release(
            tenant_id=tenant.tenant_id,
            agent_id=agent.agent_id,
        )

        await _observe(
            tenant_id=tenant.tenant_id,
            agent_id=agent.agent_id,
            target_kind=kind.value,
            target_name=name,
            status_code=502,
            started_ms=started_ms,
            outcome="routing_error",
        )

        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    except asyncio.CancelledError:
        await quota_manager.release(
            tenant_id=tenant.tenant_id,
            agent_id=agent.agent_id,
        )
        raise

    except HTTPException:
        await quota_manager.release(
            tenant_id=tenant.tenant_id,
            agent_id=agent.agent_id,
        )

        raise

    except Exception:
        await quota_manager.release(
            tenant_id=tenant.tenant_id,
            agent_id=agent.agent_id,
        )

        await _observe(
            tenant_id=tenant.tenant_id,
            agent_id=agent.agent_id,
            target_kind=kind.value,
            target_name=name,
            status_code=500,
            started_ms=started_ms,
            outcome="error",
        )

        raise


# ============================================================
# Specialized model endpoint
# ============================================================

@router.post(
    "/models/{route_name}/chat/completions",
)
async def model_chat_completions(
    request: Request,
    route_name: str,
):
    tenant, agent = _principal(
        request
    )

    try:
        get_model_router().resolve(
            route_name
        )
    except ModelRouteError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    quota = await quota_manager.acquire(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
    )

    if not quota.allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "gateway_quota_exceeded",
                "reason": quota.reason,
            },
            headers={
                "Retry-After": str(
                    quota.retry_after_seconds
                ),
            },
        )

    request.state.gateway_model_route = (
        route_name
    )

    started_ms = (
        time.perf_counter() * 1000
    )

    try:
        response = await chat_completions(request)
    except asyncio.CancelledError:
        await quota_manager.release(tenant_id=tenant.tenant_id, agent_id=agent.agent_id)
        raise
    except Exception:
        await quota_manager.release(tenant_id=tenant.tenant_id, agent_id=agent.agent_id)
        await _observe(tenant_id=tenant.tenant_id, agent_id=agent.agent_id, target_kind="model", target_name=route_name, status_code=502, started_ms=started_ms, outcome="upstream_error")
        raise

    if isinstance(
        response,
        StreamingResponse,
    ):
        return _wrap_streaming_release(
            response,
            tenant_id=tenant.tenant_id,
            agent_id=agent.agent_id,
            observation={
                "target_kind": "model",
                "target_name": route_name,
                "started_ms": started_ms,
            },
        )

    await quota_manager.release(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
    )

    status_code = getattr(
        response,
        "status_code",
        200,
    )

    await _observe(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
        target_kind="model",
        target_name=route_name,
        status_code=status_code,
        started_ms=started_ms,
        outcome=(
            "allowed"
            if status_code < 400
            else "error"
        ),
    )

    return response


# ============================================================
# Route discovery
# ============================================================

@router.get(
    "/routes",
)
async def routes(
    request: Request,
):
    tenant, agent = _principal(
        request
    )

    del tenant

    return {
        "model": get_model_router().names(),
        "agent": "tenant-scoped",
        "mcp": mcp_router.names(),
        "a2a": a2a_router.names(),
        "agent_id": str(
            agent.agent_id
        ),
    }


# ============================================================
# Quota state
# ============================================================

@router.get(
    "/quota",
)
async def quota(
    request: Request,
):
    tenant, agent = _principal(
        request
    )

    return await quota_manager.snapshot(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
    )


# ============================================================
# Metrics
# ============================================================

@router.get(
    "/metrics",
)
async def metrics(
    request: Request,
):
    _principal(
        request
    )

    return await gateway_metrics.snapshot()