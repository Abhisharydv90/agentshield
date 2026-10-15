"""Stable Phase 5 tool contracts shared by Phases 6-15."""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Awaitable, Callable, Mapping, Protocol

from app.security.context import SecurityContext


class ToolKind(StrEnum):
    INTERNAL = "internal"
    MCP = "mcp"
    BROWSER = "browser"
    CUSTOM = "custom"


class ToolHandler(Protocol):
    def __call__(
        self,
        invocation: "ToolInvocation",
        context: SecurityContext,
    ) -> Any | Awaitable[Any]: ...


def _clean_values(values: Any) -> frozenset[str]:
    if values is None:
        return frozenset()
    return frozenset(
        str(value).strip()
        for value in values
        if str(value).strip()
    )


@dataclass(frozen=True)
class ToolManifest:
    """Operator-defined description of a callable tool."""

    name: str
    version: str
    description: str = ""
    kind: ToolKind = ToolKind.INTERNAL
    operations: frozenset[str] = field(default_factory=frozenset)
    required_capabilities: frozenset[str] = field(default_factory=frozenset)
    resource_patterns: frozenset[str] = field(default_factory=frozenset)
    network_domains: frozenset[str] = field(default_factory=frozenset)
    requires_secret: bool = False
    sensitive: bool = False
    destructive: bool = False
    external_content: bool = False
    enabled: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        name = self.name.strip()
        version = self.version.strip()
        if not name:
            raise ValueError("tool name is required")
        if not version:
            raise ValueError("tool version is required")
        if len(name) > 200:
            raise ValueError("tool name is too long")
        if any(ch in name for ch in "\r\n"):
            raise ValueError("tool name contains invalid characters")
        operations = _clean_values(self.operations)
        if not operations:
            raise ValueError("tool must expose at least one operation")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "required_capabilities", _clean_values(self.required_capabilities))
        object.__setattr__(self, "resource_patterns", _clean_values(self.resource_patterns))
        object.__setattr__(self, "network_domains", frozenset(
            str(v).strip().lower().lstrip(".")
            for v in self.network_domains
            if str(v).strip()
        ))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def supports(self, operation: str) -> bool:
        return operation.strip() in self.operations

    def public_dict(self) -> dict[str, Any]:
        """Return discovery-safe metadata; never include credentials."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "kind": self.kind.value,
            "operations": sorted(self.operations),
            "required_capabilities": sorted(self.required_capabilities),
            "resource_patterns": sorted(self.resource_patterns),
            "network_domains": sorted(self.network_domains),
            "requires_secret": self.requires_secret,
            "sensitive": self.sensitive,
            "destructive": self.destructive,
            "external_content": self.external_content,
            "enabled": self.enabled,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ToolInvocation:
    """Immutable description of one attempted tool action."""

    tool_name: str
    operation: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    resource: str | None = None
    target_url: str | None = None
    approval_id: str | None = None
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if not self.tool_name.strip():
            raise ValueError("tool_name is required")
        if not self.operation.strip():
            raise ValueError("operation is required")
        object.__setattr__(self, "arguments", dict(self.arguments))

    def public_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "arguments": dict(self.arguments),
            "resource": self.resource,
            "target_url": self.target_url,
            "approval_id": self.approval_id,
        }


@dataclass(frozen=True)
class ToolResult:
    """Security-aware result from the dispatcher."""

    decision: str
    reason: str
    tool_name: str
    operation: str
    call_id: str
    value: Any = None
    proof: Mapping[str, Any] | None = None
    error_code: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "call_id": self.call_id,
            "value": self.value,
            "proof": dict(self.proof) if self.proof else None,
            "error_code": self.error_code,
            "metadata": dict(self.metadata),
        }
