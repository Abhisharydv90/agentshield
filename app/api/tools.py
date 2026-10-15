"""Phase 5 Tool Fabric discovery API.

Execution is intentionally kept behind the internal ToolDispatcher boundary.
This API exposes operator-safe discovery and registry metadata without turning
HTTP request bodies into direct arbitrary tool execution.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.tools.registry import ToolNotFoundError, get_tool_registry


router = APIRouter(prefix="/v1/tools", tags=["tools"])


@router.get("")
async def list_tools() -> dict:
    registry = get_tool_registry()
    manifests = registry.list_manifests()
    return {
        "tools": [manifest.public_dict() for manifest in manifests],
        "registry_hash": registry.snapshot_hash(),
    }


@router.get("/{tool_name}")
async def get_tool(tool_name: str) -> dict:
    try:
        registered = get_tool_registry().get(tool_name)
    except ToolNotFoundError as exc:
        raise HTTPException(status_code=404, detail="tool_not_found") from exc
    return {
        "tool": registered.manifest.public_dict(),
        "registry_hash": get_tool_registry().snapshot_hash(),
    }
