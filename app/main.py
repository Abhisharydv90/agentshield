"""
AgentShield — application entrypoint.

Wires together:

    - FastAPI application
    - Database/Redis startup checks
    - Trace middleware
    - Rate limiting
    - Trusted hosts
    - CORS
    - CSRF
    - Authentication
    - Telemetry
    - Runtime proxy
    - Tenant management
    - Authentication endpoints

Important response contract:

HTTPException detail may be either:

    "some_error"

or:

    {
        "error": "some_error",
        ...
    }

The global exception handler preserves structured error details.
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
    level=getattr(
        logging,
        settings.LOG_LEVEL.upper(),
        logging.INFO,
    ),
    format=(
        "%(asctime)s | "
        "%(levelname)-7s | "
        "%(name)-20s | "
        "%(message)s"
    ),
    datefmt="%Y-%m-%d %H:%M:%S",
)

log = logging.getLogger(
    "agentshield"
)


# ============================================================
# Lifespan
# ============================================================

@asynccontextmanager
async def lifespan(
    app: FastAPI,
) -> AsyncIterator[None]:

    log.info("=" * 62)

    log.info(
        "  AgentShield starting · env=%s · service=%s",
        settings.ENV,
        settings.SERVICE_NAME,
    )

    log.info("=" * 62)

    # --------------------------------------------------------
    # PostgreSQL
    # --------------------------------------------------------

    try:

        from sqlalchemy import text

        from app.db.session import async_session

        async with async_session() as session:

            await session.execute(
                text("SELECT 1")
            )

        log.info(
            "✓ Postgres reachable"
        )

    except Exception as exc:

        log.warning(
            "✗ Postgres unreachable — %s",
            exc,
        )

    # --------------------------------------------------------
    # Redis
    # --------------------------------------------------------

    try:

        from app.security.pii.vault import (
            _get_redis,
        )

        redis = _get_redis()

        if redis is not None:

            await redis.ping()

            log.info(
                "✓ Redis reachable"
            )

        else:

            log.warning(
                "✗ Redis client failed to initialize"
            )

    except Exception as exc:

        log.warning(
            "✗ Redis unreachable — %s",
            exc,
        )

    yield

    log.info(
        "AgentShield shutting down"
    )


# ============================================================
# Application
# ============================================================

_is_prod = settings.ENV == "prod"


app = FastAPI(
    title="AgentShield",
    version="0.2.0",
    description=(
        "Autonomous Agent Firewall & Evaluation Gateway. "
        "A zero-trust proxy that intercepts, evaluates, "
        "and secures bidirectional traffic between AI "
        "agents, LLM providers, and enterprise tools."
    ),
    docs_url=(
        None
        if _is_prod
        else "/docs"
    ),
    redoc_url=(
        None
        if _is_prod
        else "/redoc"
    ),
    openapi_url=(
        None
        if _is_prod
        else "/openapi.json"
    ),
    lifespan=lifespan,
)


# ============================================================
# Trace middleware
# ============================================================

class TraceMiddleware:
    """
    Pure ASGI trace middleware.

    Safe for SSE and streaming responses.
    """

    def __init__(
        self,
        app: Any,
    ) -> None:

        self.app = app

    async def __call__(
        self,
        scope: dict,
        receive: Any,
        send: Any,
    ) -> None:

        if scope["type"] != "http":

            await self.app(
                scope,
                receive,
                send,
            )

            return

        headers = {
            key.decode(
                "latin-1"
            ).lower():
                value.decode(
                    "latin-1"
                )
            for key, value
            in scope.get(
                "headers",
                [],
            )
        }

        incoming_trace_id = headers.get(
            "x-trace-id"
        )

        trace_id = (
            incoming_trace_id
            or str(uuid.uuid4())
        )

        state = scope.setdefault(
            "state",
            {},
        )

        state["trace_id"] = trace_id

        start = time.perf_counter()

        status_code_holder: dict[
            str,
            int,
        ] = {
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
                            "utf-8"
                        ),
                    )
                )

                message[
                    "headers"
                ] = response_headers

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

            status_code = (
                status_code_holder[
                    "code"
                ]
                or 500
            )

            level = (
                logging.WARNING
                if status_code >= 400
                else logging.INFO
            )

            log.log(
                level,
                "%s %s · %d · %.2fms · trace=%s",
                method,
                path,
                status_code,
                duration_ms,
                trace_id,
            )


# ============================================================
# Middleware configuration
#
# Starlette add_middleware() prepends middleware.
#
# LAST added = OUTERMOST.
#
# Execution:
#
#   Trace
#      ↓
#   RateLimit
#      ↓
#   TrustedHost
#      ↓
#   CORS
#      ↓
#   CSRF
#      ↓
#   Auth
#      ↓
#   Routes
# ============================================================

_allowed_hosts = (
    ["*"]
    if not _is_prod
    else [
        "agentshield.app",
        "*.agentshield.app",
        "*.up.railway.app",
        "*.vercel.app",
    ]
)


if _is_prod:

    _allow_origins = [
        "https://agentshield.app",
        "https://www.agentshield.app",
        "https://agentshield-woad.vercel.app",
    ]

    _allow_origin_regex = (
        r"https://.*\.vercel\.app"
    )

else:

    _allow_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]

    _allow_origin_regex = None


# ------------------------------------------------------------
# Inner → outer
# ------------------------------------------------------------

app.add_middleware(
    AuthMiddleware
)

app.add_middleware(
    CSRFMiddleware
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_origin_regex=_allow_origin_regex,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=["*"],
    expose_headers=[
        "X-Trace-Id",
        "X-Response-Time",
    ],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=_allowed_hosts,
)

app.add_middleware(
    RateLimitMiddleware
)

app.add_middleware(
    TraceMiddleware
)


# ============================================================
# HTTP exception handler
# ============================================================

@app.exception_handler(
    StarletteHTTPException
)
async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:

    trace_id = getattr(
        request.state,
        "trace_id",
        None,
    )

    detail = exc.detail

    # --------------------------------------------------------
    # Structured error
    #
    # Preserve dictionary details rather than wrapping them
    # inside {"error": "http_error", "detail": ...}.
    # --------------------------------------------------------

    if isinstance(
        detail,
        dict,
    ):

        body = dict(
            detail
        )

        # Ensure a stable top-level error exists.
        if not body.get(
            "error"
        ):

            body["error"] = (
                "http_error"
            )

        body["status"] = (
            exc.status_code
        )

    # --------------------------------------------------------
    # String error
    # --------------------------------------------------------

    else:

        body = {
            "error":
                str(detail),
            "status":
                exc.status_code,
        }

    # --------------------------------------------------------
    # Trace ID
    # --------------------------------------------------------

    if trace_id:

        body["trace_id"] = (
            trace_id
        )

    return JSONResponse(
        status_code=exc.status_code,
        content=body,
        headers={
            "Cache-Control":
                "no-store",
        },
    )


# ============================================================
# Unexpected exception handler
# ============================================================

@app.exception_handler(
    Exception
)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    trace_id = getattr(
        request.state,
        "trace_id",
        None,
    )

    log.exception(
        "Unhandled error on %s %s · trace=%s",
        request.method,
        request.url.path,
        trace_id,
    )

    return JSONResponse(
        status_code=500,
        content={
            "error":
                "internal_server_error",
            "trace_id":
                trace_id,
            "message":
                (
                    "An unexpected error occurred. "
                    "Contact support with the trace ID."
                ),
        },
        headers={
            "Cache-Control":
                "no-store",
        },
    )


# ============================================================
# Routers
# ============================================================

from app.api.telemetry import (
    router as telemetry_router,
)

from app.proxy.router import (
    router as proxy_router,
)

from app.api.auth import (
    router as auth_router,
)

from app.api.tenant import (
    router as tenant_router,
)


app.include_router(
    telemetry_router
)

app.include_router(
    proxy_router
)

app.include_router(
    auth_router
)

app.include_router(
    tenant_router
)


# ============================================================
# Root / metadata
# ============================================================

@app.get(
    "/",
    tags=["meta"],
)
async def root() -> dict:

    return {
        "service":
            "agentshield",
        "version":
            app.version,
        "description":
            (
                "Autonomous Agent Firewall "
                "& Evaluation Gateway"
            ),
        "docs":
            (
                "/docs"
                if not _is_prod
                else None
            ),
        "health":
            "/health",
        "readiness":
            "/ready",
        "api":
            "/v1",
    }


# ============================================================
# Health
# ============================================================

@app.get(
    "/health",
    tags=["meta"],
)
async def health() -> dict:

    return {
        "status":
            "ok",
        "env":
            settings.ENV,
        "service":
            settings.SERVICE_NAME,
        "version":
            app.version,
    }


# ============================================================
# Readiness
# ============================================================

@app.get(
    "/ready",
    tags=["meta"],
)
async def readiness() -> JSONResponse:

    checks: dict[
        str,
        bool,
    ] = {
        "postgres":
            False,
        "redis":
            False,
    }

    # --------------------------------------------------------
    # PostgreSQL
    # --------------------------------------------------------

    try:

        from sqlalchemy import text

        from app.db.session import (
            async_session,
        )

        async with async_session() as session:

            await session.execute(
                text("SELECT 1")
            )

        checks[
            "postgres"
        ] = True

    except Exception as exc:

        log.warning(
            "Readiness: postgres unreachable — %s",
            exc,
        )

    # --------------------------------------------------------
    # Redis
    # --------------------------------------------------------

    try:

        from app.security.pii.vault import (
            _get_redis,
        )

        redis = _get_redis()

        if redis is not None:

            await redis.ping()

            checks[
                "redis"
            ] = True

    except Exception as exc:

        log.warning(
            "Readiness: redis unreachable — %s",
            exc,
        )

    all_ok = all(
        checks.values()
    )

    return JSONResponse(
        status_code=(
            200
            if all_ok
            else 503
        ),
        content={
            "status":
                (
                    "ready"
                    if all_ok
                    else "not_ready"
                ),
            "checks":
                checks,
            "version":
                app.version,
        },
    )


# ============================================================
# Development-only routes
# ============================================================

if not _is_prod:

    from sqlalchemy import (
        desc,
        select,
    )

    from app.db.models import (
        SecurityEvent,
        Tenant,
    )

    from app.db.session import (
        async_session,
    )

    from app.policy.dsl import (
        EXAMPLE_POLICY,
    )

    from app.policy.engine import (
        evaluate_policy,
    )

    from app.security.judge.contract import (
        NormalizedToolCall,
    )

    from app.security.judge.evaluate import (
        execute_tool_with_judge,
    )

    from app.security.judge.normalize import (
        normalize_tool_call,
    )

    from app.security.judge.stream_buffer import (
        StreamingToolCallGate,
    )

    from app.telemetry.audit import (
        write_event,
    )

    async def _first_tenant_id():

        async with async_session() as session:

            row = (
                await session.execute(
                    select(
                        Tenant
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()

            return (
                row.tenant_id
                if row
                else None
            )


    @app.get(
        "/test/judge",
        tags=["dev"],
    )
    async def test_judge() -> dict:

        malicious_call = {
            "name":
                "db.query",
            "args": {
                "query":
                    (
                        "SELECT * FROM users; "
                        "DROP TABLE users; --"
                    )
            },
        }

        normalized = (
            normalize_tool_call(
                malicious_call
            )
        )

        try:

            normalized_call = (
                NormalizedToolCall(
                    **normalized
                )
            )

            return {
                "status":
                    "allowed (BUG!)",
                "normalized":
                    normalized_call.model_dump(),
            }

        except ValueError:

            return {
                "status":
                    "blocked",
                "reason":
                    "smuggling_detected",
                "normalized":
                    normalized,
            }


    @app.get(
        "/test/policy",
        tags=["dev"],
    )
    async def test_policy() -> dict:

        malicious = {
            "name":
                "db.query",
            "args": {
                "query":
                    (
                        "SELECT * FROM users; "
                        "DROP TABLE users; --"
                    )
            },
        }

        benign = {
            "name":
                "db.query",
            "args": {
                "query":
                    "SELECT * FROM billing_invoices",
                "table":
                    "billing_invoices",
            },
        }

        normalized_malicious = (
            normalize_tool_call(
                malicious
            )
        )

        normalized_benign = (
            normalize_tool_call(
                benign
            )
        )

        results: dict[
            str,
            Any,
        ] = {}

        try:

            NormalizedToolCall(
                **normalized_malicious
            )

            results[
                "malicious"
            ] = (
                "BUG: Normalizer allowed it!"
            )

        except ValueError:

            results[
                "malicious"
            ] = (
                "BLOCKED BY NORMALIZER"
            )

        try:

            normalized_call = (
                NormalizedToolCall(
                    **normalized_benign
                )
            )

            results[
                "benign"
            ] = evaluate_policy(
                normalized_call,
                EXAMPLE_POLICY,
            ).model_dump()

        except Exception as exc:

            results[
                "benign"
            ] = str(exc)

        return results


    @app.get(
        "/test/stream_buffer",
        tags=["dev"],
    )
    async def test_stream_buffer() -> dict:

        gate = (
            StreamingToolCallGate()
        )

        chunks = [
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id":
                                        "call_1",
                                    "function": {
                                        "name":
                                            "db.query",
                                        "arguments":
                                            (
                                                '{"query": '
                                                '"SELECT * '
                                            ),
                                    },
                                }
                            ],
                        },
                        "finish_reason":
                            None,
                    }
                ]
            },
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {
                                        "arguments":
                                            (
                                                "FROM users; "
                                                "DROP "
                                            ),
                                    },
                                }
                            ],
                        },
                        "finish_reason":
                            None,
                    }
                ]
            },
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {
                                        "arguments":
                                            (
                                                "TABLE users; "
                                                '--"}'
                                            ),
                                    },
                                }
                            ],
                        },
                        "finish_reason":
                            "tool_calls",
                    }
                ]
            },
        ]

        accumulated: list[
            dict
        ] = []

        for chunk in chunks:

            _, completed = (
                gate.feed(
                    chunk
                )
            )

            accumulated.extend(
                completed
            )

        return {
            "completed_tool_calls":
                accumulated,
        }


    @app.get(
        "/test/audit",
        tags=["dev"],
    )
    async def test_audit() -> dict:

        tenant_id = (
            await _first_tenant_id()
        )

        if tenant_id is None:

            return {
                "error":
                    "no_tenant_in_db"
            }

        async with async_session() as session:

            event_one = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=None,
                threat_category=
                    "injection_attempt",
                action_taken="blocked",
                evaluator_reasoning=
                    "Test event 1",
            )

            event_two = await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=None,
                threat_category=
                    "unauthorized_tool",
                action_taken="blocked",
                evaluator_reasoning=
                    "Test event 2",
            )

        return {
            "event1_hash":
                event_one.record_hash,
            "event2_hash":
                event_two.record_hash,
            "event2_prev_hash":
                event_two.prev_hash,
            "chain_valid":
                (
                    event_two.prev_hash
                    == event_one.record_hash
                ),
        }


    @app.get(
        "/test/circuit_breaker",
        tags=["dev"],
    )
    async def test_circuit_breaker() -> dict:

        tenant_id = (
            await _first_tenant_id()
        )

        if tenant_id is None:

            return {
                "error":
                    "no_tenant_in_db"
            }

        malicious = {
            "name":
                "db.query",
            "args": {
                "query":
                    (
                        "SELECT * FROM users; "
                        "DROP TABLE users; --"
                    )
            },
        }

        benign = {
            "name":
                "db.query",
            "args": {
                "query":
                    (
                        "SELECT * FROM "
                        "billing_invoices"
                    ),
                "table":
                    "billing_invoices",
            },
        }

        return {
            "malicious":
                await execute_tool_with_judge(
                    raw_tool_call=
                        malicious,
                    policy=
                        EXAMPLE_POLICY,
                    policy_version=
                        "1.0.0",
                    tenant_id=
                        tenant_id,
                    trace_id=
                        "test-cb-malicious",
                ),
            "benign":
                await execute_tool_with_judge(
                    raw_tool_call=
                        benign,
                    policy=
                        EXAMPLE_POLICY,
                    policy_version=
                        "1.0.0",
                    tenant_id=
                        tenant_id,
                    trace_id=
                        "test-cb-benign",
                ),
        }