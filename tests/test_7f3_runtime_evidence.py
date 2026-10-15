"""
7F-3 runtime evidence tests.

Proves that audit decisions produce content-addressed EvidenceNode records
atomically and without duplicating raw evaluator reasoning into evidence
metadata.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.db.models import EvidenceNode, SecurityEvent, Tenant
from app.db.session import async_session
from app.security.evidence.hashing import fingerprint_evidence
from app.telemetry import audit


async def _create_tenant() -> uuid.UUID:
    async with async_session() as session:
        tenant = Tenant(
            slug=(
                "7f3-runtime-"
                f"{uuid.uuid4().hex[:12]}"
            ),
            name="7F-3 Runtime Evidence Test",
        )
        session.add(tenant)
        await session.commit()
        return tenant.tenant_id


async def _delete_tenant(tenant_id: uuid.UUID) -> None:
    async with async_session() as session:
        tenant = await session.get(Tenant, tenant_id)
        if tenant is not None:
            await session.delete(tenant)
        await session.commit()


@pytest.mark.asyncio
async def test_audit_event_creates_linked_runtime_evidence():
    tenant_id = await _create_tenant()

    try:
        reasoning = "DROP TABLE customer_records"

        async with async_session() as session:
            event = await audit.write_event(
                session=session,
                tenant_id=tenant_id,
                request_id="7f3-runtime-001",
                threat_category="destructive",
                action_taken="blocked",
                evaluator_reasoning=reasoning,
            )

            payload = {
                "tenant_id": str(tenant_id),
                "request_id": "7f3-runtime-001",
                "timestamp": audit.canonical_timestamp(
                    event.timestamp
                ),
                "threat_category": "destructive",
                "action_taken": "blocked",
                "evaluator_reasoning": reasoning,
            }

            result = await session.execute(
                select(EvidenceNode).where(
                    EvidenceNode.tenant_id == tenant_id
                )
            )
            nodes = result.scalars().all()

        assert len(nodes) == 1

        node = nodes[0]
        assert node.security_event_id == event.event_id
        assert node.tenant_id == tenant_id
        assert node.trace_id == "7f3-runtime-001"
        assert node.node_type == "security_event"
        assert node.schema_version == "1"
        assert node.source == "audit"
        assert node.artifact_hash == fingerprint_evidence(payload)

        assert node.metadata_redacted["event_id"] == str(event.event_id)
        assert node.metadata_redacted["record_hash"] == event.record_hash
        assert node.metadata_redacted["prev_hash"] == event.prev_hash
        assert node.metadata_redacted["threat_category"] == "destructive"
        assert node.metadata_redacted["action_taken"] == "blocked"
        assert "evaluator_reasoning" not in node.metadata_redacted
        assert node.metadata_redacted["reason_hash"] == fingerprint_evidence(
            {"reason": reasoning}
        )
    finally:
        await _delete_tenant(tenant_id)


@pytest.mark.asyncio
async def test_runtime_evidence_failure_rolls_back_audit_event(monkeypatch):
    tenant_id = await _create_tenant()

    try:
        def fail_evidence(*, session, event, payload):
            raise RuntimeError("evidence_write_failed")

        monkeypatch.setattr(
            audit,
            "record_runtime_evidence",
            fail_evidence,
        )

        with pytest.raises(RuntimeError, match="evidence_write_failed"):
            async with async_session() as session:
                await audit.write_event(
                    session=session,
                    tenant_id=tenant_id,
                    request_id="7f3-atomicity",
                    threat_category="test",
                    action_taken="blocked",
                    evaluator_reasoning="atomicity check",
                )

        async with async_session() as session:
            event_result = await session.execute(
                select(SecurityEvent).where(
                    SecurityEvent.tenant_id == tenant_id
                )
            )
            evidence_result = await session.execute(
                select(EvidenceNode).where(
                    EvidenceNode.tenant_id == tenant_id
                )
            )

            assert event_result.scalars().all() == []
            assert evidence_result.scalars().all() == []
    finally:
        await _delete_tenant(tenant_id)
