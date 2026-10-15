"""AURAGENT Phase 12 — Ecosystem API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict

from app.ecosystem.contracts import (
    EcosystemKind,
    EcosystemManifest,
    RegistryEntry,
)
from app.ecosystem.manifest import safe_public_manifest
from app.ecosystem.registry import EcosystemRegistry
from app.ecosystem.service import EcosystemService


router = APIRouter(
    prefix="/v1/ecosystem",
    tags=["ecosystem"],
)

_registry = EcosystemRegistry()
_service = EcosystemService(_registry)


class RegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: EcosystemManifest


def _tenant_present(request: Request) -> None:
    if getattr(request.state, "tenant", None) is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )


def _role(request: Request) -> str:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authenticated user required",
        )
    role = getattr(user, "role", None)
    return str(getattr(role, "value", role) or "").casefold()


def _require_admin(request: Request) -> None:
    _tenant_present(request)
    if _role(request) not in {"owner", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ecosystem registration requires owner/admin",
        )


@router.get("/discover", response_model=list[RegistryEntry])
async def discover(
    request: Request,
    kind: EcosystemKind | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=250),
) -> list[RegistryEntry]:
    _tenant_present(request)
    return await _service.discover(kind=kind, limit=limit)


@router.post("/register", response_model=RegistryEntry)
async def register(
    body: RegistrationRequest,
    request: Request,
) -> RegistryEntry:
    _require_admin(request)
    try:
        return await _service.register(manifest=body.manifest)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@router.post("/disable/{entry_id}")
async def disable(entry_id: str, request: Request) -> dict[str, str]:
    _require_admin(request)
    try:
        await _service.disable(entry_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    return {"entry_id": entry_id, "status": "disabled"}


@router.get("/manifest/example")
async def example_manifest(request: Request) -> dict:
    _tenant_present(request)
    # Discovery helper only. It contains no credential, secret, or authority data.
    draft = EcosystemManifest(
        publisher="auragent",
        name="example",
        version="1.0.0",
        kind=EcosystemKind.INTEGRATION,
        description="Example ecosystem descriptor; not an executable integration.",
        content_sha256="",
    )
    from app.ecosystem.manifest import with_computed_hash

    return safe_public_manifest(with_computed_hash(draft))
