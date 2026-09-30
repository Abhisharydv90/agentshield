"""
AgentShield — application entrypoint.

Wires together:
  - FastAPI app with lifespan management
  - Middleware stack: trace, rate limit, trusted hosts, CORS, CSRF, auth
  - Routers: telemetry, proxy, auth, tenant, meta
  - Global exception handlers with structured JSON responses
  - Dev-only routes (gated behind settings.ENV != "prod")
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.middleware.auth import AuthMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.ratelimit import RateLimitMiddleware


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-7s | %(name)-20s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("agentshield")


# ============================================================
# Lifespan
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info("=" * 62)
    log.info(
        "  AgentShield starting · env=%s · service=%s",
        settings.ENV,
        settings.SERVICE_NAME,
    )
    log.info("=" * 62)

    try:
        from sqlalchemy import text
        from app.db.session import async_session
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        log.info("✓ Postgres reachable")
    except Exception as e:
        log.warning("✗ Postgres unreachable — %s", e)

    try:
        from app.security.pii.vault import _get_redis
        r = _get_redis()
        if r is not None:
            await r.ping()
            log.info("✓ Redis reachable")
        else:
            log.warning("✗ Redis client failed to initialize")
    except Exception as e:
        log.warning("✗ Redis unreachable — %s", e)

    yield

    log.info("AgentShield shutting down")


# ============================================================
# App
# ============================================================

_is_prod = settings.ENV == "prod"

app = FastAPI(
    title="AgentShield",
    version="0.2.0",
    description=(
        "Autonomous Agent Firewall & Evaluation Gateway. "
        "A zero-trust proxy that intercepts, evaluates, and secures bidirectional "
        "traffic between AI agents, LLM providers, and enterprise tools."
    ),
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
    lifespan=lifespan,
)


# ============================================================
# Trace middleware — pure ASGI so SSE passes through untouched
# ============================================================

class TraceMiddleware:
    """Pure ASGI middleware. Safe for SSE / chunked responses."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode().lower(): v.decode()
            for k, v in scope.get("headers", [])
        }
        trace_id = headers.get("x-trace-id") or str(uuid.uuid4())

        state = scope.setdefault("state", {})
        state["trace_id"] = trace_id

        start = time.perf_counter()
        status_code_holder: dict[str, int] = {"code": 0}

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start":
                status_code_holder["code"] = message.get("status", 0)
                response_headers = list(message.get("headers", []))
                response_headers.append((b"x-trace-id", trace_id.encode()))
                duration_ms = (time.perf_counter() - start) * 1000
                response_headers.append(
                    (b"x-response-time", f"{duration_ms:.2f}ms".encode())
                )
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            path = scope.get("path", "")
            method = scope.get("method", "")
            code = status_code_holder["code"] or 500
            level = logging.WARNING if code >= 400 else logging.INFO
            log.log(
                level,
                "%s %s · %d · %.2fms · trace=%s",
                method,
                path,
                code,
                duration_ms,
                trace_id,
            )


# ============================================================
# Middleware stack
#
# Starlette semantics: add_middleware() PREPENDS. The LAST call is OUTERMOST.
# We add innermost → outermost so the execution order is:
#
#   Trace → RateLimit → TrustedHost → CORS → CSRF → Auth → routes
#
# Trace must be outermost so every response (including errors) gets a
# trace ID. RateLimit next — cheap, kills floods before any work happens.
# TrustedHost before CORS so bad hosts die early. CORS before CSRF/Auth
# so preflight OPTIONS short-circuits and never hits session checks.
# Auth innermost so it wraps only the routes that actually need identity.
# ============================================================

_allowed_hosts = ["*"] if not _is_prod else [
    "agentshield.app",
    "*.agentshield.app",
    "*.up.railway.app",
    "*.vercel.app",
]

_prod_origins = [
    "https://agentshield.app",
    "https://www.agentshield.app",
    "https://agentshield-woad.vercel.app",
]
_dev_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
]
_allow_origins = _prod_origins if _is_prod else _dev_origins
_allow_origin_regex = r"https://.*\.vercel\.app" if _is_prod else None

# --- Add INNERMOST first ---
app.add_middleware(AuthMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_origin_regex=_allow_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Trace-Id", "X-Response-Time"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)
app.add_middleware(RateLimitMiddleware)
# --- OUTERMOST last ---
app.add_middleware(TraceMiddleware)


# ============================================================
# Exception handlers
# ============================================================

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None)
    detail = exc.detail
    if isinstance(detail, str):
        body = {"error": detail, "status": exc.status_code}
    else:
        body = {"error": "http_error", "status": exc.status_code, "detail": detail}
    if trace_id:
        body["trace_id"] = trace_id
    return JSONResponse(status_code=exc.status_code, content=body)


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None)
    log.exception(
        "Unhandled error on %s %s · trace=%s",
        request.method,
        request.url.path,
        trace_id,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "trace_id": trace_id,
            "message": "An unexpected error occurred. Contact support with the trace ID.",
        },
    )


# ============================================================
# Routers
# ============================================================

from app.api.telemetry import router as telemetry_router
from app.proxy.router import router as proxy_router
from app.api.auth import router as auth_router
from app.api.tenant import router as tenant_router

app.include_router(telemetry_router)
app.include_router(proxy_router)
app.include_router(auth_router)
app.include_router(tenant_router)


# ============================================================
# Meta endpoints
# ============================================================

@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "service": "agentshield",
        "version": app.version,
        "description": "Autonomous Agent Firewall & Evaluation Gateway",
        "docs": "/docs" if not _is_prod else None,
        "health": "/health",
        "readiness": "/ready",
        "api": "/v1",
    }


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {
        "status": "ok",
        "env": settings.ENV,
        "service": settings.SERVICE_NAME,
        "version": app.version,
    }


@app.get("/ready", tags=["meta"])
async def readiness() -> JSONResponse:
    checks: dict[str, bool] = {"postgres": False, "redis": False}

    try:
        from sqlalchemy import text
        from app.db.session import async_session
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        checks["postgres"] = True
    except Exception as e:
        log.warning("Readiness: postgres unreachable — %s", e)

    try:
        from app.security.pii.vault import _get_redis
        r = _get_redis()
        if r is not None:
            await r.ping()
            checks["redis"] = True
    except Exception as e:
        log.warning("Readiness: redis unreachable — %s", e)

    all_ok = all(checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={
            "status": "ready" if all_ok else "not_ready",
            "checks": checks,
            "version": app.version,
        },
    )


# ============================================================
# Dev-only routes
# ============================================================

if not _is_prod:
    from sqlalchemy import select, desc
    from app.security.judge.evaluate import execute_tool_with_judge
    from app.security.judge.normalize import normalize_tool_call
    from app.security.judge.contract import NormalizedToolCall
    from app.security.judge.stream_buffer import StreamingToolCallGate
    from app.policy.dsl import EXAMPLE_POLICY
    from app.policy.engine import evaluate_policy
    from app.db.session import async_session
    from app.telemetry.audit import write_event
    from app.db.models import SecurityEvent, Tenant

    async def _first_tenant_id():
        """Dev helper — grab any tenant for audit writes."""
        async with async_session() as session:
            row = (
                await session.execute(select(Tenant).limit(1))
            ).scalar_one_or_none()
            return row.tenant_id if row else None

    @app.get("/test/judge", tags=["dev"])
    async def test_judge() -> dict:
        malicious_call = {
            "name": "db.query",
            "args": {"query": "SELECT * FROM users; DROP TABLE users; --"},
        }
        normalized = normalize_tool_call(malicious_call)
        try:
            nc = NormalizedToolCall(**normalized)
            return {"status": "allowed (BUG!)", "normalized": nc.model_dump()}
        except ValueError:
            return {
                "status": "blocked",
                "reason": "smuggling_detected",
                "normalized": normalized,
            }

    @app.get("/test/policy", tags=["dev"])
    async def test_policy() -> dict:
        malicious = {
            "name": "db.query",
            "args": {"query": "SELECT * FROM users; DROP TABLE users; --"},
        }
        benign = {
            "name": "db.query",
            "args": {
                "query": "SELECT * FROM billing_invoices",
                "table": "billing_invoices",
            },
        }
        nm = normalize_tool_call(malicious)
        nb = normalize_tool_call(benign)
        results: dict[str, Any] = {}
        try:
            NormalizedToolCall(**nm)
            results["malicious"] = "BUG: Normalizer allowed it!"
        except ValueError:
            results["malicious"] = "BLOCKED BY NORMALIZER"
        try:
            nc = NormalizedToolCall(**nb)
            results["benign"] = evaluate_policy(nc, EXAMPLE_POLICY).model_dump()
        except Exception as e:
            results["benign"] = f"ERROR: {e}"
        return results

    @app.get("/test/stream_buffer", tags=["dev"])
    async def test_stream_buffer() -> dict:
        gate = StreamingToolCallGate()
        chunks = [
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "db.query", "arguments": "{\"query\": \"SELECT * "}}]}, "finish_reason": None}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "FROM users; DROP "}}]}, "finish_reason": None}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "TABLE users; --\"}"}}]}, "finish_reason": "tool_calls"}]},
        ]
        accumulated: list[dict] = []
        for c in chunks:
            _, completed = gate.feed(c)
            accumulated.extend(completed)
        return {"completed_tool_calls": accumulated}

    @app.get("/test/audit", tags=["dev"])
    async def test_audit() -> dict:
        tenant_id = await _first_tenant_id()
        if tenant_id is None:
            return {"error": "no_tenant_in_db"}
        async with async_session() as session:
            e1 = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=None,
                threat_category="injection_attempt",
                action_taken="blocked",
                evaluator_reasoning="Test event 1",
            )
            e2 = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=None,
                threat_category="unauthorized_tool",
                action_taken="blocked",
                evaluator_reasoning="Test event 2",
            )
        return {
            "event1_hash": e1.record_hash,
            "event2_hash": e2.record_hash,
            "event2_prev_hash": e2.prev_hash,
            "chain_valid": e2.prev_hash == e1.record_hash,
        }

    @app.get("/test/circuit_breaker", tags=["dev"])
    async def test_circuit_breaker() -> dict:
        tenant_id = await _first_tenant_id()
        if tenant_id is None:
            return {"error": "no_tenant_in_db"}
        malicious = {
            "name": "db.query",
            "args": {"query": "SELECT * FROM users; DROP TABLE users; --"},
        }
        benign = {
            "name": "db.query",
            "args": {
                "query": "SELECT * FROM billing_invoices",
                "table": "billing_invoices",
            },
        }
        return {
            "malicious": await execute_tool_with_judge(
                raw_tool_call=malicious,
                policy=EXAMPLE_POLICY,
                policy_version="1.0.0",
                tenant_id=tenant_id,
                trace_id="test-cb-malicious",
            ),
            "benign": await execute_tool_with_judge(
                raw_tool_call=benign,
                policy=EXAMPLE_POLICY,
                policy_version="1.0.0",
                tenant_id=tenant_id,
                trace_id="test-cb-benign",
            ),
        }