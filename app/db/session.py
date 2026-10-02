"""
Async SQLAlchemy session factory.

Database TLS is environment-aware:

Development:
    PostgreSQL may run without TLS.

Staging/Production:
    TLS is required.

Tests:
    NullPool is used to avoid event-loop/pool reuse problems.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.config import settings


_is_test = os.getenv("AGENTSHIELD_TESTING") == "1"


# ---------------------------------------------------------
# Engine configuration
# ---------------------------------------------------------

_engine_kwargs: dict = {
    "echo": False,
    "future": True,
}


# ---------------------------------------------------------
# PostgreSQL connection configuration
# ---------------------------------------------------------

if settings.DATABASE_URL.startswith(
    "postgresql+asyncpg://"
):
    connect_args: dict = {
        # Required when using PgBouncer/transaction pooling.
        "statement_cache_size": 0,
    }

    if settings.DATABASE_REQUIRE_SSL:
        connect_args["ssl"] = "require"

    _engine_kwargs["connect_args"] = connect_args


# ---------------------------------------------------------
# Test vs production pooling
# ---------------------------------------------------------

if _is_test:
    _engine_kwargs["poolclass"] = NullPool
else:
    _engine_kwargs["pool_pre_ping"] = True


# ---------------------------------------------------------
# Engine
# ---------------------------------------------------------

engine = create_async_engine(
    settings.DATABASE_URL,
    **_engine_kwargs,
)


# ---------------------------------------------------------
# Session factory
# ---------------------------------------------------------

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ---------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


# ---------------------------------------------------------
# Shutdown helper
# ---------------------------------------------------------

async def dispose_engine() -> None:
    """
    Dispose all database connections.

    Called during application shutdown.
    """

    await engine.dispose()