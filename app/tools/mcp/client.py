"""Minimal MCP Streamable HTTP client boundary.

The client is deliberately transport-focused. Authorization belongs to the
AURAGENT Tool Dispatcher before a call is made. The client never interprets an
MCP server response as granting authority to the agent.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx


class MCPError(RuntimeError):
    """Base MCP integration error."""


class MCPProtocolError(MCPError):
    """Returned JSON-RPC error from an MCP server."""


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    url: str
    protocol_version: str = "2026-07-28"
    headers: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("MCP server URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("MCP URLs may not contain embedded credentials")
        if parsed.scheme == "http" and not self.allow_insecure_http:
            raise ValueError("insecure HTTP MCP transport is disabled")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        object.__setattr__(self, "headers", dict(self.headers))


class MCPClient:
    """JSON-RPC client for MCP Streamable HTTP endpoints."""

    def __init__(self, config: MCPServerConfig, *, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._client = client
        self._owned_client = client is None
        self.session_id: str | None = None
        self._request_id = 0

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=False,
            )
        return self._client

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _headers(self, method: str, *, name: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": self.config.protocol_version,
            "Mcp-Method": method,
            **dict(self.config.headers),
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if name:
            headers["Mcp-Name"] = name
        return headers

    async def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        name: str | None = None,
    ) -> dict[str, Any]:
        request_id = self._next_id()
        body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            body["params"] = dict(params)

        client = await self._get_client()
        try:
            response = await client.post(
                self.config.url,
                headers=self._headers(method, name=name),
                json=body,
            )
        except httpx.HTTPError as exc:
            raise MCPError("MCP transport failure") from exc

        if response.status_code >= 400:
            raise MCPError(f"MCP HTTP failure: {response.status_code}")

        session_id = response.headers.get("mcp-session-id")
        if session_id:
            self.session_id = session_id

        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise MCPError("MCP response was not JSON") from exc

        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            raise MCPError("invalid MCP JSON-RPC envelope")

        if payload.get("error") is not None:
            error = payload["error"]
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message") if isinstance(error, dict) else "MCP error"
            raise MCPProtocolError(f"MCP error {code}: {message}")

        result = payload.get("result")
        return dict(result) if isinstance(result, dict) else {"value": result}

    async def initialize(self, *, client_name: str = "auragent", client_version: str = "0.5.0") -> dict[str, Any]:
        result = await self.request(
            "initialize",
            {
                "protocolVersion": self.config.protocol_version,
                "capabilities": {"tools": {}}
                ,"clientInfo": {"name": client_name, "version": client_version},
            },
        )
        return result

    async def list_tools(self) -> dict[str, Any]:
        return await self.request("tools/list")

    async def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return await self.request(
            "tools/call",
            {
                "name": name,
                "arguments": dict(arguments or {}),
            },
            name=name,
        )

    async def close(self) -> None:
        if self._client is not None and self._owned_client:
            await self._client.aclose()
        self._client = None
