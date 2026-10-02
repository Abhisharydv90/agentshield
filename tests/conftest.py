"""
Pytest configuration.

AgentShield has shared asynchronous infrastructure such as database and
Redis clients. The complete async test suite therefore runs on one
session-scoped event loop.

We intentionally do NOT redefine pytest-asyncio's event_loop fixture,
because newer pytest-asyncio versions deprecate that pattern.
"""

from __future__ import annotations

import os

# Must happen before application/database modules are imported.
os.environ["AGENTSHIELD_TESTING"] = "1"

import pytest
import pytest_asyncio


def pytest_collection_modifyitems(items) -> None:
    """
    Run every asyncio test on the same session-scoped event loop.

    pytest-asyncio 0.24 supports loop_scope on the asyncio marker. This gives
    us the same practical behavior as the old custom session event_loop
    fixture without redefining pytest-asyncio internals.
    """
    session_scope_marker = pytest.mark.asyncio(
        loop_scope="session"
    )

    for item in items:
        if pytest_asyncio.is_async_test(item):
            item.add_marker(
                session_scope_marker,
                append=False,
            )


@pytest_asyncio.fixture
async def _dispose_engine_after_test():
    """
    Release database connections after each test.

    The event loop itself remains session-scoped, while the SQLAlchemy engine
    is disposed between tests so connections do not leak between cases.
    """
    yield

    from app.db.session import engine

    await engine.dispose()