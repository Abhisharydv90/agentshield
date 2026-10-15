"""
AURAGENT runtime singleton/bootstrap.

One application process owns one RuntimeEngine composition.

Phase 13 can move the underlying execution/storage primitives to
distributed infrastructure without changing the public bootstrap API.
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.runtime import RuntimeEngine
from app.runtime.executor import (
    UnconfiguredExecutor,
)


_runtime_engine: RuntimeEngine | None = None
_runtime_lock = asyncio.Lock()


async def get_runtime_engine(
    *,
    executor: Any | None = None,
) -> RuntimeEngine:
    """
    Return the process-local RuntimeEngine singleton.
    """

    global _runtime_engine

    async with _runtime_lock:
        if _runtime_engine is None:
            selected_executor = (
                executor
                if executor is not None
                else UnconfiguredExecutor().execute
            )

            _runtime_engine = (
                RuntimeEngine.create(
                    executor=selected_executor,
                )
            )

        return _runtime_engine


async def start_runtime(
    *,
    executor: Any | None = None,
) -> RuntimeEngine:
    engine = await get_runtime_engine(
        executor=executor
    )

    await engine.start()

    return engine


async def stop_runtime() -> None:
    global _runtime_engine

    async with _runtime_lock:
        if _runtime_engine is None:
            return

        await _runtime_engine.stop()
        _runtime_engine = None