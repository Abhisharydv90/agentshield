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


class PIIVaultUnavailableError(RuntimeError):
    """
    Raised when the authoritative PII vault cannot safely be used.

    Callers should treat this as a fail-closed condition: the protected
    request must not continue to an upstream LLM or tool.
    """


_redis: redis.Redis | None = None
_redis_failed = False


def _get_redis() -> redis.Redis | None:
    """
    Lazily create the Redis client.

    Client construction itself does not prove that Redis is reachable;
    callers performing security-sensitive operations must use
    _require_redis().
    """
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
    Return a healthy Redis client or fail closed.
    """
    client = _get_redis()

    if client is None:
        raise PIIVaultUnavailableError(
            "PII vault unavailable: Redis client could not be initialized."
        )

    try:
        await client.ping()
    except Exception as exc:
        raise PIIVaultUnavailableError(
            "PII vault unavailable: Redis health check failed."
        ) from exc

    return client


class PIIVault:
    """
    Authoritative Redis-backed PII storage.

    No raw PII is retained in application memory as a fallback.
    """

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
        Build a tenant-scoped Redis key without putting the raw tenant
        identifier into Redis key names.
        """
        tenant_hash = hashlib.sha256(
            tenant.encode("utf-8")
        ).hexdigest()[:24]

        return (
            "agentshield:pii:"
            f"{tenant_hash}:"
            f"{trace_id}"
        )

    async def store(
        self,
        trace_id: str,
        tenant: str,
        mapping: dict[str, str],
    ) -> None:
        """
        Persist placeholder -> original mappings with TTL.

        Failure is propagated as PIIVaultUnavailableError so the caller
        can stop processing the protected request.
        """
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

        except PIIVaultUnavailableError:
            raise

        except Exception as exc:
            raise PIIVaultUnavailableError(
                "PII vault write failed."
            ) from exc

    async def get_mapping(
        self,
        trace_id: str,
        tenant: str,
    ) -> dict[str, str]:
        """
        Retrieve the placeholder mapping for a trace.
        """
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
            raise PIIVaultUnavailableError(
                "PII vault read failed."
            ) from exc

        return dict(result)

    async def rehydrate(
        self,
        text: str,
        trace_id: str,
        tenant: str,
    ) -> str:
        """
        Replace placeholders with their original values.

        This operation is intentionally dependent on Redis being available.
        """
        mapping = await self.get_mapping(
            trace_id,
            tenant,
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

    async def clear(
        self,
        trace_id: str,
        tenant: str,
    ) -> None:
        """
        Remove the stored mapping.
        """
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
            raise PIIVaultUnavailableError(
                "PII vault cleanup failed."
            ) from exc

    async def health(
        self,
    ) -> dict[str, Any]:
        """
        Report Redis health without raising.

        This is intended for health/readiness endpoints, not for security
        decisions during request processing.
        """
        client = _get_redis()

        if client is None:
            return {
                "backend": "redis",
                "redis_ok": False,
            }

        try:
            await client.ping()

            return {
                "backend": "redis",
                "redis_ok": True,
            }

        except Exception as exc:
            return {
                "backend": "redis",
                "redis_ok": False,
                "error": str(exc),
            }


vault = PIIVault(
    ttl=settings.PII_VAULT_TTL
)