"""Tenant-independent operator tool registry.

The registry is intentionally process-local in Phase 5. Phase 11/13 may place
its control state in a durable control plane and distributed cache while keeping
this contract stable.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable

from app.security.identity.crypto import sha256_hex
from app.tools.contracts import ToolHandler, ToolManifest


class ToolRegistryError(ValueError):
    """Base registry exception."""


class ToolNotFoundError(ToolRegistryError):
    """Raised when a requested tool is absent."""


@dataclass(frozen=True)
class RegisteredTool:
    manifest: ToolManifest
    handler: ToolHandler


class ToolRegistry:
    """Thread/event-loop safe enough for an async application process."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        manifest: ToolManifest,
        handler: ToolHandler,
        *,
        replace: bool = False,
    ) -> None:
        if not callable(handler):
            raise ToolRegistryError("tool handler must be callable")
        async with self._lock:
            if manifest.name in self._tools and not replace:
                raise ToolRegistryError(f"tool already registered: {manifest.name}")
            self._tools[manifest.name] = RegisteredTool(manifest, handler)

    async def unregister(self, name: str) -> None:
        async with self._lock:
            self._tools.pop(name.strip(), None)

    def get(self, name: str) -> RegisteredTool:
        tool = self._tools.get(name.strip())
        if tool is None:
            raise ToolNotFoundError(name)
        return tool

    def get_optional(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name.strip())

    def list_manifests(self, *, include_disabled: bool = False) -> list[ToolManifest]:
        manifests = [
            item.manifest
            for item in self._tools.values()
            if include_disabled or item.manifest.enabled
        ]
        return sorted(manifests, key=lambda item: (item.name, item.version))

    def snapshot_hash(self) -> str:
        payload = [manifest.public_dict() for manifest in self.list_manifests(include_disabled=True)]
        return sha256_hex(payload)


_default_registry = ToolRegistry()


def get_tool_registry() -> ToolRegistry:
    return _default_registry
