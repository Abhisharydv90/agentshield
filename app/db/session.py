"""
AURAGENT database session boundary.

This module is the single SQLAlchemy database boundary used across
AURAGENT Phases 0-15.

Design goals:
- Async SQLAlchemy.
- Environment-aware PostgreSQL TLS.
- PgBouncer-safe asyncpg configuration.
- NullPool for tests.
- Transaction rollback on dependency failures.
- Explicit transaction context for background/runtime services.
- Cheap database health checks.
- Clean application shutdown.

Important:
This module must remain domain-neutral. Runtime, gateway, trust,
memory, evidence, control-plane, enterprise, and research layers
must use this boundary instead of creating their own engines.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.config import settings


# ============================================================
# Environment
# ============================================================

_IS_TEST = os.getenv("AGENTSHIELD_TESTING") == "1"

_DATABASE_URL = str(settings.DATABASE_URL)

_IS_POSTGRES_ASYNCPG = _DATABASE_URL.startswith(
    "postgresql+asyncpg://"
)


# ============================================================
# Engine configuration
# ============================================================

_ENGINE_KWARGS: dict = {
    "echo": False,
}


if _IS_POSTGRES_ASYNCPG:
    connect_args: dict = {
        # Required for PgBouncer / transaction pooling.
        "statement_cache_size": 0,
    }

    if settings.DATABASE_REQUIRE_SSL:
        connect_args["ssl"] = "require"

    _ENGINE_KWARGS["connect_args"] = connect_args


if _IS_TEST:
    # Avoid connection-pool/event-loop reuse across tests.
    _ENGINE_KWARGS["poolclass"] = NullPool
else:
    # Detect stale/dead connections before handing them to callers.
    _ENGINE_KWARGS["pool_pre_ping"] = True


# ============================================================
# Engine
# ============================================================

engine = create_async_engine(
    _DATABASE_URL,
    **_ENGINE_KWARGS,
)


# ============================================================
# Session factory
# ============================================================

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


# ============================================================
# FastAPI dependency
# ============================================================

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI database dependency.

    The dependency does NOT auto-commit. Individual service operations
    decide their transaction boundary explicitly.

    On an exception inside the request, the session is rolled back so
    the connection is returned cleanly to the pool.
    """

    async with async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# ============================================================
# Explicit transaction scope
# ============================================================

@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """
    Transactional async session scope for services/background jobs.

    Usage:

        async with session_scope() as session:
            session.add(...)
            ...

    Successful exit commits.
    Exceptional exit rolls back.
    """

    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ============================================================
# Health check
# ============================================================

async def database_healthcheck() -> bool:
    """
    Return True when the configured database accepts a basic query.

    This function deliberately performs no mutation.
    """

    try:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


# ============================================================
# Engine shutdown
# ============================================================

async def dispose_engine() -> None:
    """
    Dispose the SQLAlchemy engine and all pooled connections.

    Called from application shutdown/lifespan handling.
    """

    await engine.dispose()