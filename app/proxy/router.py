"""
AgentShield runtime proxy.

Request path:

    API Key
        ↓
    Agent Identity
        ↓
    Agent status
        ↓
    agent:invoke
        ↓
    inbound security
        ↓
    upstream LLM
        ↓
    proposed tool-call authorization
        ↓
    Security Decision Engine
        ↓
    downstream Agent
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
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
from sqlalchemy import select, update

from app.config import settings
from app.db.models import Agent, Policy as PolicyModel
from app.db.session import async_session
from app.middleware.trace import get_trace_id
from app.policy.dsl import (
    EXAMPLE_POLICY,
    Policy,
    policy_from_db_rules,
)
from app.proxy.outbound import (
    authorize_non_streaming_response,
    process_outbound_stream,
)
from app.security.capabilities import (
    Capability,
    require_capability,
)
from app.security.injection.detector import (
    scan_inbound,
)
from app.security.pii.redactor import (
    get_redactor,
)
from app.telemetry.audit import (
    write_event,
)


router = APIRouter(
    prefix="/v1",
    tags=["proxy"],
)


# ============================================================
# Policy
# ============================================================

async def _load_active_policy(
    tenant_id,
) -> tuple[Policy, str]:

    async with async_session() as session:

        row = (
            await session.execute(
                select(PolicyModel)
                .where(
                    PolicyModel.tenant_id
                    == tenant_id
                )
                .where(
                    PolicyModel.active.is_(True)
                )
                .order_by(
                    PolicyModel.updated_at.desc()
                )
                .limit(1)
            )
        ).scalar_one_or_none()

    if row is None:

        return (
            EXAMPLE_POLICY,
            "fallback",
        )

    return (
        policy_from_db_rules(
            row.rules
        ),
        row.version,
    )


# ============================================================
# Agent activity
# ============================================================

async def _touch_agent(
    agent_id,
    tenant_id,
) -> None:

    try:

        async with async_session() as session:

            await session.execute(
                update(Agent)
                .where(
                    Agent.agent_id
                    == agent_id
                )
                .where(
                    Agent.tenant_id
                    == tenant_id
                )
                .where(
                    Agent.status
                    == "active"
                )
                .values(
                    last_seen_at=(
                        datetime.now(
                            timezone.utc
                        )
                    )
                )
            )

            await session.commit()

    except Exception:
        pass


# ============================================================
# Runtime endpoint
# ============================================================

@router.post(
    "/chat/completions"
)
async def chat_completions(
    request: Request,
):

    trace_id = get_trace_id(
        request
    )

    tenant = getattr(
        request.state,
        "tenant",
        None,
    )

    if tenant is None:

        raise HTTPException(
            status_code=401,
            detail="no_tenant",
        )

    agent = getattr(
        request.state,
        "agent",
        None,
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

    # --------------------------------------------------------
    # Gateway invocation capability
    # --------------------------------------------------------

    require_capability(
        agent.scopes or [],
        Capability.AGENT_INVOKE,
    )

    await _touch_agent(
        agent.agent_id,
        tenant.tenant_id,
    )

    tenant_id = tenant.tenant_id
    tenant_slug = tenant.slug

    # IMPORTANT:
    #
    # This authenticated Agent ID is now carried through the complete
    # downstream authorization path.
    agent_id = agent.agent_id

    agent_scopes = list(
        agent.scopes or []
    )

    # Approval ID is only a reference to a persisted artifact.
    # The Security Decision Engine independently validates tenant,
    # identity, action fingerprint, state, and one-time consumption.
    approval_id = request.headers.get(
        "X-AgentShield-Approval-Id"
    )

    # ========================================================
    # Request body
    # ========================================================

    try:

        body = await request.json()

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail="invalid_json",
        ) from exc

    if not isinstance(
        body,
        dict,
    ):

        raise HTTPException(
            status_code=400,
            detail="request_body_must_be_object",
        )

    # ========================================================
    # Layer 1 — inbound injection
    # ========================================================

    injection_verdict = await scan_inbound(
        body,
        trace_id,
        tenant_slug,
    )

    if injection_verdict.blocked:

        try:

            async with async_session() as session:

                await write_event(
                    session=session,
                    tenant_id=tenant_id,
                    request_id=trace_id,
                    threat_category=(
                        "injection_attempt"
                    ),
                    action_taken="blocked",
                    evaluator_reasoning=(
                        injection_verdict.reason
                    ),
                )

        except Exception:
            pass

        raise HTTPException(
            status_code=403,
            detail={
                "error":
                    "blocked_by_agentshield",
                "reason":
                    injection_verdict.reason,
            },
        )

    # ========================================================
    # Layer 2 — PII
    # ========================================================

    if settings.PII_ENFORCE:

        redactor = get_redactor(
            tenant=tenant_slug
        )

        body, redacted_map = (
            await redactor.redact(
                body,
                trace_id,
            )
        )

        if redacted_map:

            try:

                async with async_session() as session:

                    await write_event(
                        session=session,
                        tenant_id=tenant_id,
                        request_id=trace_id,
                        threat_category=(
                            "pii_leak"
                        ),
                        action_taken=(
                            "redacted"
                        ),
                        evaluator_reasoning=(
                            "redacted "
                            f"{len(redacted_map)} "
                            "entities"
                        ),
                    )

            except Exception:
                pass

    # ========================================================
    # Layer 3 — policy
    # ========================================================

    (
        policy,
        policy_version,
    ) = await _load_active_policy(
        tenant_id
    )

    # ========================================================
    # Upstream
    # ========================================================

    headers = {
        "Authorization":
            f"Bearer {settings.UPSTREAM_KEY}",
        "Content-Type":
            "application/json",
    }

    client = httpx.AsyncClient(
        timeout=settings.UPSTREAM_TIMEOUT
    )

    try:

        upstream_req = client.build_request(
            "POST",
            (
                f"{settings.UPSTREAM_URL}"
                "/v1/chat/completions"
            ),
            json=body,
            headers=headers,
        )

        upstream_resp = (
            await client.send(
                upstream_req,
                stream=True,
            )
        )

    except Exception as exc:

        await client.aclose()

        raise HTTPException(
            status_code=502,
            detail="upstream_unavailable",
        ) from exc

    is_streaming = bool(
        body.get(
            "stream",
            False,
        )
    )

    tools_requested = bool(
        body.get(
            "tools"
        )
        or body.get(
            "functions"
        )
    )

    # ========================================================
    # Streaming tool path
    # ========================================================

    if (
        is_streaming
        and tools_requested
    ):

        async def authorized_stream():

            try:

                async for chunk in (
                    process_outbound_stream(
                        upstream_iterator=
                            upstream_resp.aiter_bytes(),
                        policy=
                            policy,
                        policy_version=
                            policy_version,
                        trace_id=
                            trace_id,
                        tenant_id=
                            tenant_id,
                        agent_scopes=
                            agent_scopes,
                        agent_id=
                            agent_id,
                        approval_id=
                            approval_id,
                    )
                ):

                    yield chunk

            finally:

                await client.aclose()

        return StreamingResponse(
            authorized_stream(),
            media_type=
                "text/event-stream",
            headers={
                "X-Trace-Id":
                    trace_id,
                "Cache-Control":
                    "no-cache",
            },
        )

    # ========================================================
    # Non-streaming responses
    # ========================================================

    if not is_streaming:

        try:

            response_body = (
                await upstream_resp.aread()
            )

            # Never inspect upstream error responses as tool proposals.
            if upstream_resp.status_code < 400:

                denial = (
                    await authorize_non_streaming_response(
                        body=
                            response_body,
                        policy=
                            policy,
                        policy_version=
                            policy_version,
                        trace_id=
                            trace_id,
                        tenant_id=
                            tenant_id,
                        agent_scopes=
                            agent_scopes,
                        agent_id=
                            agent_id,
                        approval_id=
                            approval_id,
                    )
                )

                if denial is not None:

                    return JSONResponse(
                        status_code=(
                            403
                        ),
                        content=denial,
                    )

            content_type = (
                upstream_resp.headers.get(
                    "content-type",
                    "application/json",
                )
            )

            return Response(
                content=
                    response_body,
                status_code=
                    upstream_resp.status_code,
                media_type=
                    content_type.split(
                        ";",
                        1,
                    )[0],
                headers={
                    "X-Trace-Id":
                        trace_id,
                },
            )

        finally:

            await client.aclose()

    # ========================================================
    # Streaming without tools
    # ========================================================

    async def passthrough():

        try:

            async for chunk in (
                upstream_resp.aiter_raw()
            ):

                yield chunk

        finally:

            await client.aclose()

    return StreamingResponse(
        passthrough(),
        status_code=
            upstream_resp.status_code,
        headers={
            "X-Trace-Id":
                trace_id,
        },
        media_type=
            "text/event-stream",
    )