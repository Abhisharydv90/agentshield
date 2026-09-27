"""
Inbound proxy. Forwards /v1/chat/completions to the upstream LLM after
running the request through the AgentShield security pipeline.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.config import settings
from app.middleware.trace import get_trace_id
from app.security.injection.detector import scan_inbound
from app.security.pii.redactor import get_redactor
from app.proxy.outbound import process_outbound_stream
from app.policy.dsl import EXAMPLE_POLICY
from app.db.session import async_session
from app.telemetry.audit import write_event

router = APIRouter(prefix="/v1", tags=["proxy"])


@router.post("/chat/completions")
async def chat_completions(request: Request):
    trace_id = get_trace_id(request)
    tenant = getattr(request.state, "tenant", None)
    if tenant is None:
        raise HTTPException(status_code=401, detail="no_tenant")

    tenant_id = tenant.tenant_id
    tenant_slug = tenant.slug

    body = await request.json()

    # --- Layer 1: Inbound injection scan ---
    verdict = await scan_inbound(body, trace_id, tenant_slug)
    if verdict.blocked:
        try:
            async with async_session() as session:
                await write_event(
                    session=session,
                    tenant_id=tenant_id,
                    request_id=trace_id,
                    threat_category="injection_attempt",
                    action_taken="blocked",
                    evaluator_reasoning=verdict.reason,
                )
        except Exception as e:
            print(f"CRITICAL: audit write failed: {e}")

        raise HTTPException(
            status_code=403,
            detail={"error": "Blocked by AgentShield", "reason": verdict.reason},
        )

    # --- Layer 2: PII redaction ---
    if settings.PII_ENFORCE:
        redactor = get_redactor(tenant=tenant_slug)
        body, redacted_map = await redactor.redact(body, trace_id)
        if redacted_map:
            try:
                async with async_session() as session:
                    await write_event(
                        session=session,
                        tenant_id=tenant_id,
                        request_id=trace_id,
                        threat_category="pii_leak",
                        action_taken="redacted",
                        evaluator_reasoning=f"redacted {len(redacted_map)} entities",
                    )
            except Exception as e:
                print(f"WARN: PII audit log failed: {e}")

    # --- Forward to upstream LLM ---
    headers = {
        "Authorization": f"Bearer {settings.UPSTREAM_KEY}",
        "Content-Type": "application/json",
    }

    client = httpx.AsyncClient(timeout=settings.UPSTREAM_TIMEOUT)
    upstream_req = client.build_request(
        "POST",
        f"{settings.UPSTREAM_URL}/v1/chat/completions",
        json=body,
        headers=headers,
    )
    upstream_resp = await client.send(upstream_req, stream=True)

    is_streaming = body.get("stream", False)
    tools_requested = "tools" in body or "functions" in body

    if is_streaming and tools_requested:
        return StreamingResponse(
            process_outbound_stream(
                upstream_iterator=upstream_resp.aiter_bytes(),
                policy=EXAMPLE_POLICY,
                policy_version="1.0.0",
                trace_id=trace_id,
                tenant_id=tenant_id,
            ),
            media_type="text/event-stream",
            headers={"X-Trace-Id": trace_id},
        )

    async def passthrough():
        try:
            async for chunk in upstream_resp.aiter_raw():
                yield chunk
        finally:
            await client.aclose()

    return StreamingResponse(
        passthrough(),
        status_code=upstream_resp.status_code,
        headers=dict(upstream_resp.headers),
    )