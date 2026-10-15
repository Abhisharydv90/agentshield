"""Process-local ecosystem registry with deterministic identity.

The registry is intentionally not an authority store. A later durable registry
can persist these exact contracts without changing callers.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone

from .contracts import EcosystemKind, EcosystemManifest, RegistryEntry
from .manifest import verify_manifest


class RegistryError(ValueError):
    pass


class DuplicateEntryError(RegistryError):
    pass


class EcosystemRegistry:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._entries: dict[str, RegistryEntry] = {}

    @staticmethod
    def entry_id(manifest: EcosystemManifest) -> str:
        digest = hashlib.sha256(
            (
                f"{manifest.kind.value}:"
                f"{manifest.publisher.casefold()}:"
                f"{manifest.name.casefold()}:"
                f"{manifest.version}"
            ).encode("utf-8")
        ).hexdigest()
        return f"eco_{digest[:24]}"

    async def register(self, manifest: EcosystemManifest) -> RegistryEntry:
        verify_manifest(manifest)

        entry = RegistryEntry(
            entry_id=self.entry_id(manifest),
            kind=manifest.kind,
            name=manifest.name,
            version=manifest.version,
            publisher=manifest.publisher,
            description=manifest.description,
            digest_sha256=manifest.content_sha256,
            verified=True,
            enabled=True,
            registered_at=datetime.now(timezone.utc),
            metadata=dict(manifest.metadata),
        )

        async with self._lock:
            existing = self._entries.get(entry.entry_id)
            if existing is not None:
                if existing.digest_sha256 != entry.digest_sha256:
                    raise DuplicateEntryError(
                        "ecosystem entry identity already exists with a different digest"
                    )
                return existing

            self._entries[entry.entry_id] = entry
            return entry

    async def disable(self, entry_id: str) -> None:
        async with self._lock:
            entry = self._entries.get(entry_id)
            if entry is None:
                raise RegistryError("ecosystem entry not found")
            self._entries[entry_id] = entry.model_copy(
                update={"enabled": False}
            )

    async def get(self, entry_id: str) -> RegistryEntry | None:
        async with self._lock:
            return self._entries.get(entry_id)

    async def list(
        self,
        *,
        kind: EcosystemKind | None = None,
        enabled_only: bool = True,
        limit: int = 100,
    ) -> list[RegistryEntry]:
        limit = max(1, min(limit, 250))
        async with self._lock:
            entries = list(self._entries.values())

        entries.sort(key=lambda item: (item.registered_at, item.entry_id))

        output: list[RegistryEntry] = []
        for entry in entries:
            if kind is not None and entry.kind != kind:
                continue
            if enabled_only and not entry.enabled:
                continue
            output.append(entry)
            if len(output) >= limit:
                break
        return output

    async def snapshot_hash(self) -> str:
        entries = await self.list(enabled_only=False, limit=250)
        canonical = "\n".join(
            f"{item.entry_id}:{item.version}:{item.digest_sha256}:{item.enabled}"
            for item in entries
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
