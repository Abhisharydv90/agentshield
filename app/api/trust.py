"""AURAGENT Phase 4 trust-kernel control endpoints."""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.db.models import AgentIdentity
from app.db.session import async_session
from app.security.identity.crypto import AgentIdentityDocument, canonical_json, verify_signature

router = APIRouter(prefix="/v1/trust", tags=["trust-kernel"])


class IdentityRegistration(BaseModel):
    key_id: str = Field(min_length=1, max_length=128)
    public_key: str = Field(min_length=32, max_length=128)
    algorithm: str = Field(default="Ed25519", max_length=32)
    issued_at: int
    nonce: str = Field(min_length=16, max_length=128)
    signature: str = Field(min_length=40, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _parse_uuid(value: Any, name: str) -> uuid.UUID:
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid_{name}") from exc


@router.get("/identity")
async def get_identity(request: Request) -> dict[str, Any]:
    tenant = getattr(request.state, "tenant", None)
    agent = getattr(request.state, "agent", None)
    if tenant is None or agent is None:
        raise HTTPException(status_code=403, detail="agent_identity_required")
    async with async_session() as session:
        row = (
            await session.execute(
                select(AgentIdentity)
                .where(AgentIdentity.tenant_id == tenant.tenant_id)
                .where(AgentIdentity.agent_id == agent.agent_id)
                .where(AgentIdentity.status == "active")
                .limit(1)
            )
        ).scalar_one_or_none()
    if row is None:
        return {"registered": False, "tenant_id": str(tenant.tenant_id), "agent_id": str(agent.agent_id)}
    return {
        "registered": True,
        "tenant_id": str(row.tenant_id),
        "agent_id": str(row.agent_id),
        "key_id": row.key_id,
        "algorithm": row.algorithm,
        "public_key": row.public_key,
        "fingerprint": row.fingerprint,
        "status": row.status,
        "created_at": row.created_at.isoformat(),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
    }


@router.post("/identity/register")
async def register_identity(request: Request, body: IdentityRegistration) -> dict[str, Any]:
    tenant = getattr(request.state, "tenant", None)
    agent = getattr(request.state, "agent", None)
    if tenant is None or agent is None:
        raise HTTPException(status_code=403, detail="agent_identity_required")
    if body.algorithm != "Ed25519":
        raise HTTPException(status_code=400, detail="unsupported_identity_algorithm")

    now = int(datetime.now(timezone.utc).timestamp())
    if abs(now - int(body.issued_at)) > 300:
        raise HTTPException(status_code=400, detail="identity_registration_timestamp_out_of_window")

    signed_payload = {
        "schema": "auragent.identity-registration.v1",
        "tenant_id": str(tenant.tenant_id),
        "agent_id": str(agent.agent_id),
        "key_id": body.key_id,
        "public_key": body.public_key,
        "algorithm": body.algorithm,
        "issued_at": int(body.issued_at),
        "nonce": body.nonce,
    }
    if not verify_signature(body.public_key, canonical_json(signed_payload), body.signature):
        raise HTTPException(status_code=400, detail="invalid_identity_proof_of_possession")

    fingerprint = hashlib.sha256(base64.urlsafe_b64decode(body.public_key + "=" * ((4 - len(body.public_key) % 4) % 4))).hexdigest()
    async with async_session() as session:
        existing = (
            await session.execute(
                select(AgentIdentity)
                .where(AgentIdentity.tenant_id == tenant.tenant_id)
                .where(AgentIdentity.agent_id == agent.agent_id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is None:
            row = AgentIdentity(
                identity_id=uuid.uuid4(),
                tenant_id=tenant.tenant_id,
                agent_id=agent.agent_id,
                key_id=body.key_id,
                algorithm=body.algorithm,
                public_key=body.public_key,
                fingerprint=fingerprint,
                status="active",
                metadata_json=body.metadata,
                created_at=datetime.now(timezone.utc),
                expires_at=None,
            )
            session.add(row)
        else:
            existing.key_id = body.key_id
            existing.algorithm = body.algorithm
            existing.public_key = body.public_key
            existing.fingerprint = fingerprint
            existing.status = "active"
            existing.metadata_json = body.metadata
        await session.commit()

    return {
        "registered": True,
        "agent_id": str(agent.agent_id),
        "tenant_id": str(tenant.tenant_id),
        "key_id": body.key_id,
        "fingerprint": fingerprint,
    }
