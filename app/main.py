"""
AURAGENT — application composition root.

AURAGENT is the umbrella platform. AgentShield remains a security
component inside the wider Gateway → Runtime → Trust/Tool/Isolation →
Evidence architecture.

This file is intentionally kept as a stable composition root for
Phases 0-15. Future phase routers register through the discovery list
below so this file does not need to be rewritten every time a new
subsystem is introduced.
"""

from __future__ import annotations

import importlib
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

from starlette.types import Receive, Scope, Send

from app.config import settings
from app.middleware.trace import get_trace_id
from app.middleware.auth import AuthMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.ratelimit import RateLimitMiddleware
from app.security.pii.vault import PIIVaultUnavailableError


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
    """
    Application startup/shutdown orchestration.

    Startup order:
        infrastructure checks
            ↓
        runtime heartbeat
            ↓
        serve requests

    Shutdown:
        stop runtime first
            ↓
        release DB/runtime resources
    """

    log.info("=" * 72)
    log.info(
        "  AURAGENT starting · env=%s · service=%s",
        settings.ENV,
        settings.SERVICE_NAME,
    )
    log.info("=" * 72)

    # --------------------------------------------------------
    # PostgreSQL
    # --------------------------------------------------------

    postgres_ok = False

    try:
        from sqlalchemy import text
        from app.db.session import async_session

        async with async_session() as session:
            await session.execute(
                text("SELECT 1")
            )

        postgres_ok = True
        log.info("✓ Postgres reachable")

    except Exception as exc:
        log.warning(
            "✗ Postgres unreachable — %s",
            exc,
        )

    if settings.ENV == "prod" and not postgres_ok:
        raise RuntimeError("database_unavailable")

    # --------------------------------------------------------
    # Redis
    # --------------------------------------------------------

    try:
        from app.security.pii.vault import _get_redis

        redis_client = _get_redis()

        if redis_client is not None:
            await redis_client.ping()
            log.info("✓ Redis reachable")
        else:
            log.warning(
                "✗ Redis client failed to initialize"
            )

    except Exception as exc:
        log.warning(
            "✗ Redis unreachable — %s",
            exc,
        )

    # --------------------------------------------------------
    # Runtime heartbeat
    # --------------------------------------------------------

    runtime_started = False

    try:
        from app.runtime.bootstrap import start_runtime

        await start_runtime()

        runtime_started = True
        app.state.runtime_started = True

        log.info(
            "✓ AURAGENT runtime heartbeat started"
        )

    except Exception as exc:
        app.state.runtime_started = False

        log.error(
            "✗ AURAGENT runtime failed to start — %s",
            exc,
        )

        if settings.ENV == "prod":
            raise

    app.state.postgres_ok = postgres_ok

    try:
        yield

    finally:
        # ----------------------------------------------------
        # Stop runtime before process shutdown
        # ----------------------------------------------------

        if runtime_started:
            try:
                from app.runtime.bootstrap import stop_runtime

                await stop_runtime()

                log.info(
                    "✓ AURAGENT runtime heartbeat stopped"
                )

            except Exception as exc:
                log.warning(
                    "Runtime shutdown warning — %s",
                    exc,
                )

        try:
            from app.db.session import dispose_engine

            await dispose_engine()

            log.info(
                "✓ Database engine disposed"
            )

        except Exception as exc:
            log.warning(
                "Database shutdown warning — %s",
                exc,
            )

        log.info(
            "AURAGENT shutting down"
        )



class RequestBodyTooLargeError(Exception):
    """Raised when an incoming HTTP body exceeds the configured limit."""


class RequestBodyLimitMiddleware:
    """
    Reject oversized HTTP bodies before JSON parsing/PII processing.

    This is pure ASGI so streaming responses remain untouched.
    """

    def __init__(
        self,
        app: Any,
    ) -> None:
        self.app = app
        self.limit = int(
            settings.MAX_REQUEST_BODY_BYTES
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        headers = {
            key.decode("latin-1").lower():
            value.decode("latin-1")
            for key, value in scope.get(
                "headers",
                [],
            )
        }

        content_length = headers.get(
            "content-length"
        )

        if content_length:
            try:
                if int(content_length) > self.limit:
                    response = JSONResponse(
                        status_code=413,
                        content={
                            "error":
                                "request_body_too_large",
                            "status": 413,
                        },
                        headers={
                            "Cache-Control":
                                "no-store"
                        },
                    )

                    await response(
                        scope,
                        receive,
                        send,
                    )

                    return

            except ValueError:
                response = JSONResponse(
                    status_code=400,
                    content={
                        "error":
                            "invalid_content_length",
                        "status": 400,
                    },
                    headers={
                        "Cache-Control":
                            "no-store"
                    },
                )

                await response(
                    scope,
                    receive,
                    send,
                )

                return

        received = 0

        async def limited_receive() -> dict:
            nonlocal received

            message = await receive()

            if message["type"] != "http.request":
                return message

            body = message.get(
                "body",
                b"",
            )

            received += len(body)

            if received > self.limit:
                raise RequestBodyTooLargeError

            return message

        try:
            await self.app(
                scope,
                limited_receive,
                send,
            )

        except RequestBodyTooLargeError:
            response = JSONResponse(
                status_code=413,
                content={
                    "error":
                        "request_body_too_large",
                    "status": 413,
                },
                headers={
                    "Cache-Control":
                        "no-store"
                },
            )

            await response(
                scope,
                receive,
                send,
            )

# ============================================================
# App
# ============================================================

_is_prod = settings.ENV == "prod"

app = FastAPI(
    title="AURAGENT",
    version="0.5.0",
    description=(
        "AURAGENT — Autonomous Agent Infrastructure & Trust Fabric. "
        "AgentShield provides the security enforcement component across "
        "Gateway, Runtime, Tool, Isolation, and Evidence boundaries."
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
    """
    Pure ASGI trace middleware.

    Every HTTP request receives a bounded trace ID and every response
    receives the same trace ID plus response timing.
    """

    def __init__(
        self,
        app: Any,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        request = Request(
            scope,
            receive=receive,
        )

        trace_id = get_trace_id(
            request
        )

        state = scope.setdefault(
            "state",
            {},
        )

        state["trace_id"] = trace_id

        start = time.perf_counter()
        status_code_holder = {
            "code": 0
        }

        async def send_wrapper(
            message: dict,
        ) -> None:
            if (
                message["type"]
                == "http.response.start"
            ):
                status_code_holder[
                    "code"
                ] = message.get(
                    "status",
                    0,
                )

                response_headers = list(
                    message.get(
                        "headers",
                        [],
                    )
                )

                response_headers.append(
                    (
                        b"x-trace-id",
                        trace_id.encode(
                            "utf-8"
                        ),
                    )
                )

                duration_ms = (
                    time.perf_counter()
                    - start
                ) * 1000

                response_headers.append(
                    (
                        b"x-response-time",
                        f"{duration_ms:.2f}ms".encode(
                            "ascii"
                        ),
                    )
                )

                message["headers"] = (
                    response_headers
                )

            await send(
                message
            )

        try:
            await self.app(
                scope,
                receive,
                send_wrapper,
            )

        finally:
            duration_ms = (
                time.perf_counter()
                - start
            ) * 1000

            path = scope.get(
                "path",
                "",
            )

            method = scope.get(
                "method",
                "",
            )

            code = (
                status_code_holder[
                    "code"
                ]
                or 500
            )

            level = (
                logging.WARNING
                if code >= 400
                else logging.INFO
            )

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
#   Trace → RateLimit → TrustedHost → CORS → CSRF → Auth → BodyLimit → routes
#
# Trace is outermost so responses receive trace IDs.
# RateLimit rejects floods early.
# TrustedHost rejects untrusted hosts.
# CORS handles browser policy/preflight.
# CSRF protects browser-authenticated state-changing requests.
# Auth establishes human/agent identity.
# BodyLimit rejects oversized bodies before expensive processing.
# ============================================================

_allowed_hosts = (
    ["*"]
    if not _is_prod
    else settings.trusted_hosts
)

_prod_origins = (
    settings.cors_origins
    if _is_prod
    else [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]
)
_dev_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
]
_allow_origins = _prod_origins if _is_prod else _dev_origins
_allow_origin_regex = r"https://.*\.vercel\.app" if _is_prod else None

# --- Add INNERMOST first ---
app.add_middleware(RequestBodyLimitMiddleware)
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
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None)
    detail = exc.detail

    if isinstance(detail, str):
        body = {
            "error": detail,
            "status": exc.status_code,
        }
    elif isinstance(detail, dict):
        # Preserve structured application errors such as:
        # {"error": "capability_required", "capability": "..."}.
        # Wrapping these as {"error": "http_error", ...} would break the
        # API contract and hide the actual security decision.
        body = dict(detail)
        body.setdefault("status", exc.status_code)
    else:
        body = {
            "error": "http_error",
            "status": exc.status_code,
            "detail": detail,
        }

    if trace_id:
        body["trace_id"] = trace_id

    return JSONResponse(
        status_code=exc.status_code,
        content=body,
    )


@app.exception_handler(PIIVaultUnavailableError)
async def pii_vault_unavailable_handler(
    request: Request,
    exc: PIIVaultUnavailableError,
) -> JSONResponse:
    """PII protection is a hard security dependency; never fail open."""

    trace_id = getattr(request.state, "trace_id", None)
    log.error(
        "PII vault unavailable · trace=%s · %s",
        trace_id,
        exc,
    )
    return JSONResponse(
        status_code=503,
        content={
            "error": "pii_vault_unavailable",
            "status": 503,
            "trace_id": trace_id,
            "message": (
                "Request not forwarded because PII protection is unavailable."
            ),
        },
        headers={"Cache-Control": "no-store"},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
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
# Router registration
# ============================================================

def _include_router_module(
    module_name: str,
    *,
    required: bool = False,
) -> bool:
    """
    Register a FastAPI router from a module when available.

    Phase 0-2 core routers are required.
    Phase 3-15 routers are discovered dynamically so future phases
    can add implementations without repeatedly editing main.py.

    A module without a `router` attribute is treated as an unimplemented
    scaffold and is skipped.
    """

    try:
        module = importlib.import_module(
            module_name
        )

        candidate = getattr(
            module,
            "router",
            None,
        )

        if candidate is None:
            log.debug(
                "Skipping router without `router`: %s",
                module_name,
            )
            return False

        app.include_router(
            candidate
        )

        log.info(
            "✓ Router registered: %s",
            module_name,
        )

        return True

    except ModuleNotFoundError as exc:
        # A missing top-level optional router module is expected while
        # a future AURAGENT phase is still under construction.
        if exc.name == module_name and not required:
            log.debug(
                "Optional router not present: %s",
                module_name,
            )
            return False

        # A dependency failure inside an existing router is a real
        # application error. Production must not silently lose a route.
        raise

    except Exception:
        if required or settings.ENV == "prod":
            raise

        log.exception(
            "Optional router failed to load: %s",
            module_name,
        )

        return False


# Existing AgentShield / Phase 0-2 routers.
_REQUIRED_ROUTER_MODULES = (
    "app.api.telemetry",
    "app.proxy.router",
    "app.api.auth",
    "app.api.tenant",
    "app.api.approvals",
)

for _module in _REQUIRED_ROUTER_MODULES:
    _include_router_module(
        _module,
        required=True,
    )


# AURAGENT Phase 1-15 router discovery.
#
# Implement a `router = APIRouter(...)` in any module below and the
# composition root will pick it up automatically.
_OPTIONAL_AURAGENT_ROUTER_MODULES = (
    # Phase 1 — Development Platform
    "app.api.agents",
    "app.api.deployments",

    # Phase 2 — Runtime
    "app.api.runtime",
    "app.api.workflows",

    # Phase 3 — Gateway
    "app.gateway.router",

    # Phase 8 — Evidence administration
    "app.api.evidence_admin",

    # Phase 9 — Security Lab
    "app.api.lab",

    # Phase 10 — Investigation
    "app.api.investigation",

    # Phase 11 — Control Plane
    "app.api.control_plane",

    # Phase 12 — Ecosystem
    "app.api.ecosystem",

    # Phase 13 — Scale
    "app.api.scale",

    # Phase 14 — Enterprise
    "app.api.enterprise",

    # Phase 15 — Research
    "app.api.research",
    "app.api.trust",

    # Phase 5 — Tool Fabric
    "app.api.tools",

    # Phase 6 — Memory Fabric
    "app.api.memory",
    "app.api.isolation",
)

for _module in _OPTIONAL_AURAGENT_ROUTER_MODULES:
    _include_router_module(
        _module
    )


# ============================================================
# Meta endpoints
# ============================================================

@app.get("/", tags=["meta"])
async def root() -> dict:
    return {
        "service": settings.SERVICE_NAME,
        "platform": "AURAGENT",
        "component": "AgentShield",
        "version": app.version,
        "description": (
            "Autonomous Agent Infrastructure & Trust Fabric"
        ),
        "docs": "/docs" if not _is_prod else None,
        "health": "/health",
        "readiness": "/ready",
        "api": "/v1",
    }


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {
        "status": "ok",
        "platform": "AURAGENT",
        "component": "AgentShield",
        "env": settings.ENV,
        "service": settings.SERVICE_NAME,
        "version": app.version,
        "runtime": {
            "started": bool(
                getattr(
                    app.state,
                    "runtime_started",
                    False,
                )
            ),
        },
    }


@app.get("/ready", tags=["meta"])
async def readiness() -> JSONResponse:
    checks: dict[str, bool] = {
        "postgres": False,
        "redis": False,
        "runtime": bool(
            getattr(
                app.state,
                "runtime_started",
                False,
            )
        ),
    }

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

    # The runtime heartbeat is part of the AURAGENT control path.
    all_ok = all(checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={
            "status": "ready" if all_ok else "not_ready",
            "platform": "AURAGENT",
            "component": "AgentShield",
            "checks": checks,
            "version": app.version,
        },
    )


# ============================================================
# Dev-only routes
# ============================================================

if not _is_prod:
    from sqlalchemy import select
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
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "db.query", "arguments": '{"query": "SELECT * '}}]}, "finish_reason": None}]},
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