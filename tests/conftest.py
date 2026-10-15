"""
Pytest configuration.

AgentShield has shared asynchronous infrastructure such as database and
Redis clients. The complete async test suite therefore runs on one
session-scoped event loop.

We intentionally do NOT redefine pytest-asyncio's event_loop fixture,
because newer pytest-asyncio versions deprecate that pattern.
"""

from __future__ import annotations

import asyncio
import os

# Must happen before application/database modules are imported.
os.environ["AGENTSHIELD_TESTING"] = "1"

import pytest
import pytest_asyncio


_SESSION_EVENT_LOOP: asyncio.AbstractEventLoop | None = None


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _capture_session_event_loop():
    """Capture the single pytest-asyncio session loop used by async tests."""
    global _SESSION_EVENT_LOOP

    _SESSION_EVENT_LOOP = asyncio.get_running_loop()
    try:
        yield
    finally:
        _SESSION_EVENT_LOOP = None


@pytest.fixture(autouse=True)
def _restore_session_event_loop():
    """Restore the session loop around every test.

    Some synchronous tests call asyncio.run(), which clears the current loop
    from the Windows main-thread event-loop policy. Before the next test,
    restore the pytest-asyncio session loop so async test collection/execution
    never starts with no current event loop.
    """
    if (
        _SESSION_EVENT_LOOP is not None
        and not _SESSION_EVENT_LOOP.is_closed()
    ):
        asyncio.set_event_loop(_SESSION_EVENT_LOOP)

    yield

    if (
        _SESSION_EVENT_LOOP is not None
        and not _SESSION_EVENT_LOOP.is_closed()
    ):
        asyncio.set_event_loop(_SESSION_EVENT_LOOP)


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