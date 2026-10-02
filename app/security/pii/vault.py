"""
Secure PII vault.

Redis is the authoritative storage backend.

Security rule:

    Redis unavailable
        ->
    PII operation fails closed

There is intentionally NO raw-PII in-memory fallback.

The vault is TTL-scoped and keyed by tenant + trace.
"""

from __future__ import annotations

import hashlib
from typing import Any

import redis.asyncio as redis

from app.config import settings


# ============================================================
# Redis client
# ============================================================


_redis: redis.Redis | None = None
_redis_failed = False


def _get_redis() -> redis.Redis | None:

    global _redis
    global _redis_failed

    if _redis_failed:
        return None

    if _redis is None:

        try:

            _redis = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
            )

        except Exception:

            _redis_failed = True

            return None

    return _redis


async def _require_redis() -> redis.Redis:
    """
    Return a healthy Redis client.

    Raises RuntimeError when the secure vault is unavailable.
    """

    client = _get_redis()

    if client is None:

        raise RuntimeError(
            "PII vault unavailable: Redis client could not be initialized."
        )

    try:

        await client.ping()

    except Exception as exc:

        raise RuntimeError(
            "PII vault unavailable: Redis health check failed."
        ) from exc

    return client


# ============================================================
# Vault
# ============================================================


class PIIVault:

    def __init__(
        self,
        ttl: int = 900,
    ) -> None:

        self.ttl = ttl

    def _key(
        self,
        tenant: str,
        trace_id: str,
    ) -> str:
        """
        Construct a Redis key without exposing arbitrary tenant
        identifiers directly.

        The SHA-256 prefix keeps the key deterministic but opaque.
        """

        tenant_hash = hashlib.sha256(
            tenant.encode(
                "utf-8"
            )
        ).hexdigest()[:24]

        return (
            "agentshield:pii:"
            f"{tenant_hash}:"
            f"{trace_id}"
        )

    # ========================================================
    # Store
    # ========================================================

    async def store(
        self,
        trace_id: str,
        tenant: str,
        mapping: dict[str, str],
    ) -> None:

        if not mapping:
            return

        client = await _require_redis()

        key = self._key(
            tenant,
            trace_id,
        )

        try:

            pipe = client.pipeline()

            for (
                placeholder,
                original,
            ) in mapping.items():

                pipe.hset(
                    key,
                    placeholder,
                    original,
                )

            pipe.expire(
                key,
                self.ttl,
            )

            await pipe.execute()

        except Exception as exc:

            raise RuntimeError(
                "PII vault write failed."
            ) from exc

    # ========================================================
    # Read
    # ========================================================

    async def get_mapping(
        self,
        trace_id: str,
        tenant: str,
    ) -> dict[str, str]:

        client = await _require_redis()

        key = self._key(
            tenant,
            trace_id,
        )

        try:

            result = await client.hgetall(
                key
            )

        except Exception as exc:

            raise RuntimeError(
                "PII vault read failed."
            ) from exc

        return dict(
            result
        )

    # ========================================================
    # Rehydrate
    # ========================================================

    async def rehydrate(
        self,
        text: str,
        trace_id: str,
        tenant: str,
    ) -> str:

        mapping = (
            await self.get_mapping(
                trace_id,
                tenant,
            )
        )

        if not mapping:
            return text

        for (
            placeholder,
            original,
        ) in mapping.items():

            text = text.replace(
                placeholder,
                original,
            )

        return text

    # ========================================================
    # Cleanup
    # ========================================================

    async def clear(
        self,
        trace_id: str,
        tenant: str,
    ) -> None:

        client = await _require_redis()

        key = self._key(
            tenant,
            trace_id,
        )

        try:

            await client.delete(
                key
            )

        except Exception as exc:

            raise RuntimeError(
                "PII vault cleanup failed."
            ) from exc

    # ========================================================
    # Health
    # ========================================================

    async def health(
        self,
    ) -> dict[str, Any]:

        client = _get_redis()

        if client is None:

            return {
                "backend":
                    "redis",
                "redis_ok":
                    False,
            }

        try:

            await client.ping()

            return {
                "backend":
                    "redis",
                "redis_ok":
                    True,
            }

        except Exception as exc:

            return {
                "backend":
                    "redis",
                "redis_ok":
                    False,
                "error":
                    str(exc),
            }


# ============================================================
# Singleton
# ============================================================


vault = PIIVault(
    ttl=settings.PII_VAULT_TTL
)