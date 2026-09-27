"""
PII Vault — reversible token storage.

Redis for hot-path lookups (TTL-scoped). Falls back to an in-memory dict
if Redis is unavailable so the proxy never returns a 500 on dependency failure.
"""

from __future__ import annotations

import time
from typing import Any

import redis.asyncio as redis

from app.config import settings


# ============================================================
# Redis client — lazy init, safe to import even if Redis is down
# ============================================================

_redis: redis.Redis | None = None
_redis_failed: bool = False

# In-memory fallback: {key: (mapping, expires_at)}
_inmem: dict[str, tuple[dict[str, str], float]] = {}


def _get_redis() -> redis.Redis | None:
    """
    Return a Redis client, or None if initialization failed.

    Lazily initialized so importing this module never crashes the app
    on startup when Redis is temporarily unavailable.
    """
    global _redis, _redis_failed
    if _redis_failed:
        return None
    if _redis is None:
        try:
            _redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
        except Exception as e:
            print(f"WARN: Redis client init failed: {e}")
            _redis_failed = True
            return None
    return _redis


# ============================================================
# Vault
# ============================================================

class PIIVault:
    """Stores placeholder → original-value mappings, scoped by (tenant, trace_id)."""

    def __init__(self, ttl: int = 900) -> None:
        self.ttl = ttl

    def _key(self, tenant: str, trace_id: str) -> str:
        return f"vault:{tenant}:{trace_id}"

    # --- Write ---

    async def store(self, trace_id: str, tenant: str, mapping: dict[str, str]) -> None:
        """Persist the placeholder→original mapping with a TTL."""
        if not mapping:
            return

        key = self._key(tenant, trace_id)
        r = _get_redis()

        if r is not None:
            try:
                pipe = r.pipeline()
                for placeholder, original in mapping.items():
                    pipe.hset(key, placeholder, original)
                pipe.expire(key, self.ttl)
                await pipe.execute()
                return
            except Exception as e:
                print(f"WARN: Redis store failed, falling back to memory: {e}")

        # In-memory fallback
        existing, _ = _inmem.get(key, ({}, 0.0))
        existing.update(mapping)
        _inmem[key] = (existing, time.time() + self.ttl)

    # --- Read ---

    async def get_mapping(self, trace_id: str, tenant: str) -> dict[str, str]:
        """Return the full placeholder→original mapping."""
        key = self._key(tenant, trace_id)
        r = _get_redis()

        if r is not None:
            try:
                result = await r.hgetall(key)
                if result:
                    return dict(result)
            except Exception as e:
                print(f"WARN: Redis read failed, checking memory: {e}")

        entry = _inmem.get(key)
        if entry and entry[1] > time.time():
            return entry[0]
        return {}

    async def rehydrate(self, text: str, trace_id: str, tenant: str) -> str:
        """Replace every placeholder in the text with its original value."""
        mapping = await self.get_mapping(trace_id, tenant)
        if not mapping:
            return text
        for placeholder, original in mapping.items():
            text = text.replace(placeholder, original)
        return text

    # --- Cleanup ---

    async def clear(self, trace_id: str, tenant: str) -> None:
        """Remove a vault entry — called after successful rehydration."""
        key = self._key(tenant, trace_id)
        r = _get_redis()

        if r is not None:
            try:
                await r.delete(key)
            except Exception:
                pass

        _inmem.pop(key, None)

    # --- Diagnostics ---

    async def health(self) -> dict[str, Any]:
        """Report whether Redis is reachable. Used by /ready."""
        r = _get_redis()
        if r is None:
            return {"backend": "memory", "redis_ok": False, "entries_memory": len(_inmem)}
        try:
            await r.ping()
            return {"backend": "redis", "redis_ok": True, "entries_memory": len(_inmem)}
        except Exception as e:
            return {
                "backend": "memory",
                "redis_ok": False,
                "error": str(e),
                "entries_memory": len(_inmem),
            }


# ============================================================
# Singleton
# ============================================================

vault = PIIVault(ttl=settings.PII_VAULT_TTL)