"""MCP session lifecycle wrapper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from app.tools.mcp.client import MCPClient, MCPServerConfig


@dataclass
class MCPSession:
    config: MCPServerConfig
    client: MCPClient | None = None
    initialized: bool = False
    server_info: Mapping[str, Any] | None = None

    async def open(self) -> dict[str, Any]:
        if self.client is None:
            self.client = MCPClient(self.config)
        self.server_info = await self.client.initialize()
        self.initialized = True
        return dict(self.server_info)

    async def list_tools(self) -> dict[str, Any]:
        self._require_open()
        assert self.client is not None
        return await self.client.list_tools()

    async def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._require_open()
        assert self.client is not None
        return await self.client.call_tool(name, arguments)

    def _require_open(self) -> None:
        if not self.initialized or self.client is None:
            raise RuntimeError("MCP session is not initialized")

    async def close(self) -> None:
        if self.client is not None:
            await self.client.close()
        self.client = None
        self.initialized = False
