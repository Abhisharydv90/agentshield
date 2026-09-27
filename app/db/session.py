"""
Async SQLAlchemy session factory.

Uses NullPool during tests to prevent "Event loop is closed" errors —
pytest creates a new event loop per test, and pooled connections are
tied to whichever loop opened them.
"""

import os

from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from app.config import settings


_is_test = os.getenv("AGENTSHIELD_TESTING") == "1"

_engine_kwargs: dict = {
    "echo": False,
    "future": True,
    "connect_args": {
        "ssl": "require",
        "statement_cache_size": 0,  # required for Neon's pgbouncer
    },
}

if _is_test:
    _engine_kwargs["poolclass"] = NullPool
else:
    _engine_kwargs["pool_pre_ping"] = True

engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)

async_session = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db():
    async with async_session() as session:
        yield session