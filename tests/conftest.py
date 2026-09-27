"""
Pytest configuration.

Must set AGENTSHIELD_TESTING=1 BEFORE app.db.session is imported.
Disposes the engine after every test to release connections.
"""

import asyncio
import os

# Signal test mode to the app (enables NullPool in app.db.session)
os.environ["AGENTSHIELD_TESTING"] = "1"

import pytest


@pytest.fixture(autouse=True)
async def _dispose_engine_after_test():
    """Release all DB connections after each test."""
    yield
    from app.db.session import engine
    await engine.dispose()


@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop so tests share one loop where possible."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()