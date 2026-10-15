"""Phase 12 Ecosystem service."""

from __future__ import annotations

from .contracts import EcosystemKind, EcosystemManifest, RegistryEntry
from .manifest import verify_manifest
from .registry import EcosystemRegistry


class EcosystemService:
    """Registry facade. Registration never grants runtime authority."""

    def __init__(self, registry: EcosystemRegistry | None = None) -> None:
        self.registry = registry or EcosystemRegistry()

    async def register(self, *, manifest: EcosystemManifest) -> RegistryEntry:
        verify_manifest(manifest)
        return await self.registry.register(manifest)

    async def disable(self, entry_id: str) -> None:
        await self.registry.disable(entry_id)

    async def discover(
        self,
        *,
        kind: EcosystemKind | None = None,
        limit: int = 100,
    ) -> list[RegistryEntry]:
        return await self.registry.list(
            kind=kind,
            enabled_only=True,
            limit=limit,
        )
