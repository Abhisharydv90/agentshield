"""Bounded idempotency records for distributed request processing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone


class IdempotencyConflict(ValueError):
    pass


@dataclass(frozen=True)
class IdempotencyRecord:
    namespace: str
    key: str
    request_digest: str
    result_digest: str | None
    created_at: datetime
    expires_at: datetime | None


class InMemoryIdempotencyStore:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._records: dict[tuple[str, str], IdempotencyRecord] = {}

    async def claim(
        self,
        *,
        namespace: str,
        key: str,
        request_digest: str,
        ttl_seconds: int | None = 3600,
    ) -> tuple[bool, IdempotencyRecord]:
        if not namespace.strip() or not key.strip():
            raise ValueError("namespace and key are required")
        if len(request_digest) != 64:
            raise ValueError("request_digest must be SHA-256")
        if ttl_seconds is not None and (ttl_seconds < 1 or ttl_seconds > 86400):
            raise ValueError("ttl_seconds must be between 1 and 86400")

        now = datetime.now(timezone.utc)

        async with self._lock:
            record_key = (namespace, key)
            existing = self._records.get(record_key)

            if existing and existing.expires_at and existing.expires_at <= now:
                self._records.pop(record_key, None)
                existing = None

            if existing is not None:
                if existing.request_digest != request_digest:
                    raise IdempotencyConflict(
                        "idempotency key reused with a different request digest"
                    )
                return False, existing

            expires_at = (
                None
                if ttl_seconds is None
                else now.replace(microsecond=0)
                + __import__("datetime").timedelta(seconds=ttl_seconds)
            )
            created = IdempotencyRecord(
                namespace=namespace,
                key=key,
                request_digest=request_digest,
                result_digest=None,
                created_at=now,
                expires_at=expires_at,
            )
            self._records[record_key] = created
            return True, created

    async def complete(
        self,
        *,
        namespace: str,
        key: str,
        request_digest: str,
        result_digest: str,
    ) -> IdempotencyRecord:
        if len(result_digest) != 64:
            raise ValueError("result_digest must be SHA-256")
        async with self._lock:
            existing = self._records.get((namespace, key))
            if existing is None:
                raise KeyError("idempotency record not found")
            if existing.request_digest != request_digest:
                raise IdempotencyConflict("request digest mismatch")

            completed = IdempotencyRecord(
                namespace=existing.namespace,
                key=existing.key,
                request_digest=existing.request_digest,
                result_digest=result_digest,
                created_at=existing.created_at,
                expires_at=existing.expires_at,
            )
            self._records[(namespace, key)] = completed
            return completed

    async def get(
        self,
        *,
        namespace: str,
        key: str,
    ) -> IdempotencyRecord | None:
        async with self._lock:
            return self._records.get((namespace, key))
