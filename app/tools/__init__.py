"""AURAGENT Tool & Environment Fabric.

Phase 5 provides a security-aware tool registry and dispatcher plus explicit
MCP, browser, secret and custom-tool boundaries. Tool execution always occurs
behind a Phase 4 SecurityContext; the fabric never invents authority.
"""

from app.tools.contracts import (
    ToolHandler,
    ToolInvocation,
    ToolKind,
    ToolManifest,
    ToolResult,
)
from app.tools.registry import ToolRegistry, get_tool_registry
from app.tools.dispatcher import ToolDispatcher

__all__ = [
    "ToolHandler",
    "ToolInvocation",
    "ToolKind",
    "ToolManifest",
    "ToolResult",
    "ToolRegistry",
    "ToolDispatcher",
    "get_tool_registry",
]
