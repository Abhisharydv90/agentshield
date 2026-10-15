"""
AURAGENT model/security proxy.

This remains the security-aware data-plane path used by the original
AgentShield runtime and by the AURAGENT Gateway.

Request path:

    Gateway / direct API
        ↓
    Tenant binding
        ↓
    Agent identity
        ↓
    agent:invoke capability
        ↓
    inbound security
        ↓
    PII controls
        ↓
    active policy
        ↓
    configured model route
        ↓
    upstream model
        ↓
    outbound tool-call authorization
        ↓
    Security Decision Engine
        ↓
    audit / evidence
        ↓
    downstream agent

The proxy never trusts a client-supplied upstream URL.
Gateway model targets resolve to server-side configured routes.

The same file remains the stable model data-plane boundary for AURAGENT Phases 4-15.
Memory is handled by the Memory Fabric and never becomes authority merely
because retrieved content influences a model response. Later phases attach
through stable security, tool, isolation, evidence, and control boundaries.
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
from app.db.models import Agent, AgentIdentity, Policy as PolicyModel
from app.db.session import async_session
from app.middleware.trace import get_trace_id
from app.policy.dsl import (
    NO_ACTIVE_POLICY,
    Policy,
    policy_from_db_rules,
)
from app.gateway.routing.model import (
    ModelRouteError,
    get_model_router,
)
from app.security.context import SecurityContext
from app.security.delegation.model import AuthorityState
from app.security.kernel import AuthorityDeniedError, SecurityKernel
from app.security.proofs.authority_token import AuthorityToken, AuthorityTokenVerificationError
from app.security.proofs.policy_commitment import PolicyCommitment
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
        return NO_ACTIVE_POLICY, NO_ACTIVE_POLICY.version

    return (
        policy_from_db_rules(
            row.rules,
            name=row.name,
            version=row.version,
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
# Model route resolution
# ============================================================

def _resolve_upstream(
    request: Request,
) -> tuple[str, dict[str, str], float]:
    """
    Resolve the upstream model endpoint.

    Gateway-originated requests carry a server-populated
    `request.state.gateway_model_route`.

    Direct legacy AgentShield requests continue using UPSTREAM_URL.
    """

    gateway_route = getattr(
        request.state,
        "gateway_model_route",
        None,
    )

    if gateway_route:
        try:
            route = get_model_router().resolve(
                gateway_route
            )
        except ModelRouteError as exc:
            raise HTTPException(
                status_code=502,
                detail="model_route_unavailable",
            ) from exc

        headers = route.upstream_headers()

        # Backward-compatible default route: the existing AgentShield
        # configuration supplies UPSTREAM_KEY even when the new AURAGENT
        # route registry does not explicitly define api_key_env.
        if (
            "Authorization" not in headers
            and settings.UPSTREAM_KEY
        ):
            headers["Authorization"] = (
                f"Bearer {settings.UPSTREAM_KEY}"
            )

        return (
            route.chat_completions_url,
            headers,
            route.timeout_seconds,
        )

    return (
        (
            f"{settings.UPSTREAM_URL}"
            "/v1/chat/completions"
        ),
        {
            "Authorization":
                f"Bearer {settings.UPSTREAM_KEY}",
            "Content-Type":
                "application/json",
        },
        float(
            settings.UPSTREAM_TIMEOUT
        ),
    )




# ============================================================
# Phase 4 — authority token binding
# ============================================================

async def _bind_presented_authority(
    *,
    request: Request,
    tenant_id,
    agent,
    policy: Policy,
    policy_version: str,
    trace_id: str,
) -> SecurityContext | None:
    """Validate a self-issued or delegated signed authority-token chain."""

    raw_chain = request.headers.get(
        "X-AURAGENT-Authority-Chain"
    )
    raw_token = request.headers.get(
        "X-AURAGENT-Authority-Token"
    )

    if not raw_chain and not raw_token:
        return None

    import json

    try:
        if raw_chain:
            payload = json.loads(raw_chain)
            if not isinstance(payload, list) or not payload:
                raise ValueError("authority chain must be a non-empty list")
            token_chain = [
                AuthorityToken.from_dict(item)
                for item in payload
                if isinstance(item, dict)
            ]
            if len(token_chain) != len(payload):
                raise ValueError("authority chain item must be an object")

            if raw_token:
                leaf = AuthorityToken.from_dict(json.loads(raw_token))
                if leaf.token_hash != token_chain[-1].token_hash:
                    raise ValueError("authority chain leaf mismatch")
        else:
            token_chain = [
                AuthorityToken.from_dict(
                    json.loads(raw_token)
                )
            ]
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail="invalid_authority_token",
        ) from exc

    issuer_ids = {
        token.issuer_agent_id
        for token in token_chain
    }

    async with async_session() as session:
        identities_rows = (
            await session.execute(
                select(AgentIdentity)
                .where(AgentIdentity.tenant_id == tenant_id)
                .where(AgentIdentity.agent_id.in_(issuer_ids))
                .where(AgentIdentity.status == "active")
            )
        ).scalars().all()

        agents_rows = (
            await session.execute(
                select(Agent)
                .where(Agent.tenant_id == tenant_id)
                .where(Agent.agent_id.in_(issuer_ids))
                .where(Agent.status == "active")
            )
        ).scalars().all()

    identities = {
        row.agent_id: row
        for row in identities_rows
    }
    issuers = {
        row.agent_id: row
        for row in agents_rows
    }

    try:
        context = SecurityKernel().validate_authority_chain(
            token_chain=token_chain,
            target_agent=agent,
            issuer_identities=identities,
            issuer_agents=issuers,
            expected_policy_hash=PolicyCommitment.from_policy(
                policy,
                name=getattr(policy, "name", None),
                version=policy_version,
            ).content_hash,
            trace_id=trace_id,
        )
    except AuthorityDeniedError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc

    return context

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

        except Exception as exc:
            raise RuntimeError("security_audit_unavailable") from exc

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

            except Exception as exc:
                raise RuntimeError("security_audit_unavailable") from exc

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
    # Upstream model route
    # ========================================================

    upstream_url, upstream_headers, upstream_timeout = (
        _resolve_upstream(
            request
        )
    )

    client = httpx.AsyncClient(
        timeout=upstream_timeout,
        follow_redirects=False,
    )

    try:

        upstream_req = client.build_request(
            "POST",
            upstream_url,
            json=body,
            headers=upstream_headers,
        )

        upstream_resp = (
            await client.send(
                upstream_req,
                stream=True,
            )
        )

    except HTTPException:
        await client.aclose()
        raise

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
                "X-Content-Type-Options":
                    "nosniff",
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
                    "X-Content-Type-Options":
                        "nosniff",
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
            "X-Content-Type-Options":
                "nosniff",
        },
        media_type=
            "text/event-stream",
    )