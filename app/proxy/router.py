"""
AgentShield runtime proxy.

Runtime authentication model:

    X-API-Key
        ↓
    APIKey
        ↓
    Agent
        ↓
    Agent status
        ↓
    Capability check
        ↓
    Injection / PII / policy pipeline
        ↓
    Upstream LLM

An API key without a bound Agent cannot invoke the runtime.

An Agent without `agent:invoke` cannot invoke the runtime.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
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
from app.proxy.outbound import process_outbound_stream
from app.security.capabilities import (
    Capability,
    require_capability,
)
from app.security.injection.detector import scan_inbound
from app.security.pii.redactor import get_redactor
from app.telemetry.audit import write_event


router = APIRouter(
    prefix="/v1",
    tags=["proxy"],
)


# ============================================================
# Policy loader
# ============================================================


async def _load_active_policy(
    tenant_id,
) -> tuple[Policy, str]:

    async with async_session() as session:

        row = (
            await session.execute(
                select(
                    PolicyModel
                )
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
# Agent last-seen update
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
                    last_seen_at=
                        datetime.now(
                            timezone.utc
                        )
                )
            )

            await session.commit()

    except Exception:
        # Observability metadata must not turn an otherwise
        # authorized request into an application failure.
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

    # --------------------------------------------------------
    # Agent identity
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Agent status
    # --------------------------------------------------------

    if agent.status != "active":

        raise HTTPException(
            status_code=403,
            detail="agent_inactive",
        )

    # --------------------------------------------------------
    # Runtime capability
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

    # --------------------------------------------------------
    # Parse request
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Layer 1: inbound injection
    # --------------------------------------------------------

    verdict = await scan_inbound(
        body,
        trace_id,
        tenant_slug,
    )

    if verdict.blocked:

        try:

            async with async_session() as session:

                await write_event(
                    session=session,
                    tenant_id=tenant_id,
                    request_id=trace_id,
                    threat_category=
                        "injection_attempt",
                    action_taken="blocked",
                    evaluator_reasoning=
                        verdict.reason,
                )

        except Exception:
            pass

        raise HTTPException(
            status_code=403,
            detail={
                "error":
                    "Blocked by AgentShield",
                "reason":
                    verdict.reason,
            },
        )

    # --------------------------------------------------------
    # Layer 2: PII redaction
    # --------------------------------------------------------

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
                        threat_category=
                            "pii_leak",
                        action_taken=
                            "redacted",
                        evaluator_reasoning=
                            (
                                "redacted "
                                f"{len(redacted_map)} "
                                "entities"
                            ),
                    )

            except Exception:
                pass

    # --------------------------------------------------------
    # Layer 3: policy
    # --------------------------------------------------------

    (
        policy,
        policy_version,
    ) = await _load_active_policy(
        tenant_id
    )

    # --------------------------------------------------------
    # Upstream request
    # --------------------------------------------------------

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

    except Exception:

        await client.aclose()

        raise HTTPException(
            status_code=502,
            detail="upstream_unavailable",
        )

    is_streaming = bool(
        body.get(
            "stream",
            False,
        )
    )

    tools_requested = (
        "tools" in body
        or "functions" in body
    )

    # --------------------------------------------------------
    # Streaming tool-call path
    # --------------------------------------------------------

    if (
        is_streaming
        and tools_requested
    ):

        return StreamingResponse(
            process_outbound_stream(
                upstream_iterator=
                    upstream_resp.aiter_bytes(),
                policy=policy,
                policy_version=
                    policy_version,
                trace_id=trace_id,
                tenant_id=tenant_id,
            ),
            media_type=
                "text/event-stream",
            headers={
                "X-Trace-Id":
                    trace_id,
            },
        )

    # --------------------------------------------------------
    # Passthrough path
    #
    # Non-streaming tool-call enforcement will be hardened
    # in the next runtime-security batch.
    # --------------------------------------------------------

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
        headers=dict(
            upstream_resp.headers
        ),
    )