"""AURAGENT Phase 6 Memory Fabric API."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select

from app.db.models import Agent, Tenant
from app.db.session import async_session
from app.memory.models import MemoryCreate, MemoryKind, MemorySearchQuery, MemoryUpdate
from app.memory.store import MemoryNotFoundError, MemorySecurityError, MemoryStore, VersionConflictError
from app.security.context import SecurityContext
from app.security.kernel import SecurityKernel

router = APIRouter(prefix="/v1/memory", tags=["memory"])


MAX_MEMORY_CONTENT_CHARS = 256 * 1024
MAX_MEMORY_METADATA_BYTES = 512 * 1024
MAX_MEMORY_QUERY_CHARS = 4096


def _json_size(value: Any) -> int:
    try:
        return len(
            json.dumps(
                value,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError, OverflowError):
        return MAX_MEMORY_METADATA_BYTES + 1


class SourceInput(BaseModel):
    source_type: str = Field(default="unknown", max_length=40)
    uri: str | None = Field(default=None, max_length=2000)
    title: str | None = Field(default=None, max_length=500)
    expected_content_hash: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        max_length=50,
    )

    @model_validator(mode="after")
    def validate_metadata_budget(self):
        if _json_size(self.metadata) > MAX_MEMORY_METADATA_BYTES:
            raise ValueError("memory_source_too_large")
        return self


class MemoryCreateRequest(BaseModel):
    namespace: str = Field(min_length=1, max_length=200)
    key: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=MAX_MEMORY_CONTENT_CHARS)
    kind: MemoryKind = MemoryKind.AGENT
    source: SourceInput | None = None
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        max_length=100,
    )
    retention_days: int | None = Field(
        default=None,
        gt=0,
        le=36500,
    )
    on_poisoning: str = Field(
        default="reject",
        pattern="^(reject|quarantine)$",
    )

    @model_validator(mode="after")
    def validate_request_budget(self):
        if _json_size(self.metadata) > MAX_MEMORY_METADATA_BYTES:
            raise ValueError("memory_metadata_too_large")
        if self.source is not None and (
            _json_size(self.source.model_dump())
            > MAX_MEMORY_METADATA_BYTES
        ):
            raise ValueError("memory_source_too_large")
        return self


class MemoryUpdateRequest(BaseModel):
    content: str = Field(max_length=MAX_MEMORY_CONTENT_CHARS)
    expected_version: int = Field(gt=0)
    source: SourceInput | None = None
    metadata: dict[str, Any] | None = Field(
        default=None,
        max_length=100,
    )
    retention_days: int | None = Field(
        default=None,
        gt=0,
        le=36500,
    )
    on_poisoning: str = Field(
        default="reject",
        pattern="^(reject|quarantine)$",
    )

    @model_validator(mode="after")
    def validate_request_budget(self):
        if self.metadata is not None and (
            _json_size(self.metadata)
            > MAX_MEMORY_METADATA_BYTES
        ):
            raise ValueError("memory_metadata_too_large")
        if self.source is not None and (
            _json_size(self.source.model_dump())
            > MAX_MEMORY_METADATA_BYTES
        ):
            raise ValueError("memory_source_too_large")
        return self


class MemorySearchRequest(BaseModel):
    query: str = Field(
        min_length=1,
        max_length=MAX_MEMORY_QUERY_CHARS,
    )
    namespace: str | None = Field(default=None, max_length=200)
    kind: MemoryKind | None = None
    limit: int = Field(default=10, ge=1, le=100)
    min_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )


def _parse_uuid(value: str, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"invalid_{field}",
        ) from exc


async def _security_context(request: Request) -> SecurityContext:
    tenant = getattr(request.state, "tenant", None)
    agent = getattr(request.state, "agent", None)

    existing = getattr(request.state, "security_context", None)
    if isinstance(existing, SecurityContext):
        # Never accept a context that is inconsistent with the authenticated
        # transport principal. A forged/misbound context must fail closed.
        if (
            tenant is None
            or agent is None
            or existing.tenant_id != tenant.tenant_id
            or existing.agent_id != agent.agent_id
        ):
            raise HTTPException(
                status_code=403,
                detail="security_context_principal_mismatch",
            )
        return existing
    if tenant is None or agent is None:
        raise HTTPException(
            status_code=403,
            detail="agent_identity_required",
        )
    if agent.status != "active":
        raise HTTPException(
            status_code=403,
            detail="agent_inactive",
        )

    authority = SecurityKernel.agent_base_authority(agent)
    context = SecurityContext(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
        trace_id=getattr(request.state, "trace_id", ""),
        capabilities=frozenset(agent.scopes or []),
        authority=authority,
        policy_hash="legacy_authenticated_agent",
        authority_token_hash=None,
        provenance={
            "source": "authenticated_agent",
            "memory_phase": 6,
        },
    )
    request.state.security_context = context
    return context


def _serialize(view) -> dict[str, Any]:
    return {
        "memory_id": view.memory_id,
        "tenant_id": view.tenant_id,
        "agent_id": view.agent_id,
        "namespace": view.namespace,
        "key": view.key,
        "kind": view.kind,
        "content": view.content,
        "content_hash": view.content_hash,
        "version": view.version,
        "status": view.status,
        "trust_class": view.trust_class,
        "influence_class": view.influence_class,
        "source_id": view.source_id,
        "retention_until": view.retention_until,
        "metadata": dict(view.metadata),
    }


@router.post("")
async def create_memory(
    request: Request,
    body: MemoryCreateRequest,
) -> dict[str, Any]:
    context = await _security_context(request)

    async with async_session() as session:
        store = MemoryStore(session)

        try:
            result = await store.create(
                context,
                MemoryCreate(
                    namespace=body.namespace,
                    key=body.key,
                    content=body.content,
                    kind=body.kind,
                    source=(
                        body.source.model_dump()
                        if body.source
                        else None
                    ),
                    metadata=body.metadata,
                    retention_days=body.retention_days,
                    on_poisoning=body.on_poisoning,
                ),
            )
            await session.commit()

        except MemorySecurityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=403,
                detail=str(exc),
            ) from exc

        except Exception as exc:
            await session.rollback()
            raise HTTPException(
                status_code=500,
                detail="memory_write_failed",
            ) from exc

    return {"memory": _serialize(result)}


@router.get("/{memory_id}")
async def get_memory(
    request: Request,
    memory_id: str,
) -> dict[str, Any]:
    context = await _security_context(request)
    parsed = _parse_uuid(memory_id, "memory_id")

    async with async_session() as session:
        store = MemoryStore(session)

        try:
            result = await store.get(
                context,
                parsed,
            )

        except MemoryNotFoundError as exc:
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            ) from exc

        except MemorySecurityError as exc:
            raise HTTPException(
                status_code=403,
                detail=str(exc),
            ) from exc

    return {"memory": _serialize(result)}


@router.put("/{memory_id}")
async def update_memory(
    request: Request,
    memory_id: str,
    body: MemoryUpdateRequest,
) -> dict[str, Any]:
    context = await _security_context(request)
    parsed = _parse_uuid(memory_id, "memory_id")

    async with async_session() as session:
        store = MemoryStore(session)

        try:
            result = await store.update(
                context,
                parsed,
                MemoryUpdate(
                    content=body.content,
                    expected_version=body.expected_version,
                    source=(
                        body.source.model_dump()
                        if body.source
                        else None
                    ),
                    metadata=body.metadata,
                    retention_days=body.retention_days,
                    on_poisoning=body.on_poisoning,
                ),
            )
            await session.commit()

        except VersionConflictError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=409,
                detail=str(exc),
            ) from exc

        except MemoryNotFoundError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            ) from exc

        except MemorySecurityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=403,
                detail=str(exc),
            ) from exc

        except Exception as exc:
            await session.rollback()
            raise HTTPException(
                status_code=500,
                detail="memory_update_failed",
            ) from exc

    return {"memory": _serialize(result)}


@router.delete("/{memory_id}")
async def delete_memory(
    request: Request,
    memory_id: str,
) -> dict[str, Any]:
    context = await _security_context(request)
    parsed = _parse_uuid(memory_id, "memory_id")

    async with async_session() as session:
        store = MemoryStore(session)

        try:
            await store.delete(
                context,
                parsed,
            )
            await session.commit()

        except MemoryNotFoundError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            ) from exc

        except MemorySecurityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=403,
                detail=str(exc),
            ) from exc

        except Exception as exc:
            await session.rollback()
            raise HTTPException(
                status_code=500,
                detail="memory_delete_failed",
            ) from exc

    return {
        "deleted": True,
        "memory_id": str(parsed),
    }


@router.post("/search")
async def search_memory(
    request: Request,
    body: MemorySearchRequest,
) -> dict[str, Any]:
    context = await _security_context(request)

    async with async_session() as session:
        store = MemoryStore(session)

        try:
            results = await store.search(
                context,
                MemorySearchQuery(
                    query=body.query,
                    namespace=body.namespace,
                    kind=body.kind,
                    limit=body.limit,
                    min_score=body.min_score,
                ),
            )

        except MemorySecurityError as exc:
            raise HTTPException(
                status_code=403,
                detail=str(exc),
            ) from exc

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail="memory_search_failed",
            ) from exc

    return {
        "results": [
            {
                **_serialize(result.memory),
                "score": result.score,
                "integrity_verified": result.integrity_verified,
                "poisoning_score": result.poisoning_score,
                "provenance": dict(result.provenance),
            }
            for result in results
        ]
    }
