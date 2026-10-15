"""Deterministic research decision-proof construction."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from .contracts import ContainmentMode, ResearchDecisionProof


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def build_decision_proof(
    *,
    tenant_id: UUID,
    trace_id: str,
    subject_id: str,
    policy_hash: str,
    authority_before: Any,
    authority_after: Any,
    provenance: Any,
    decision: str,
    reason: str,
    containment_mode: ContainmentMode | None = None,
) -> ResearchDecisionProof:
    if len(policy_hash) != 64:
        raise ValueError("policy_hash must be a SHA-256 digest")

    proof_id = uuid4()
    created_at = datetime.now(timezone.utc)

    before_hash = _digest(authority_before)
    after_hash = _digest(authority_after)
    provenance_hash = _digest(provenance)

    canonical = json.dumps(
        {
            "proof_id": str(proof_id),
            "tenant_id": str(tenant_id),
            "trace_id": trace_id,
            "subject_id": subject_id,
            "policy_hash": policy_hash,
            "authority_before_hash": before_hash,
            "authority_after_hash": after_hash,
            "provenance_hash": provenance_hash,
            "decision": decision,
            "reason": reason,
            "containment_mode": (
                containment_mode.value if containment_mode else None
            ),
            "created_at": created_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return ResearchDecisionProof(
        proof_id=proof_id,
        tenant_id=tenant_id,
        trace_id=trace_id,
        subject_id=subject_id,
        policy_hash=policy_hash,
        authority_before_hash=before_hash,
        authority_after_hash=after_hash,
        provenance_hash=provenance_hash,
        decision=decision,
        reason=reason,
        containment_mode=containment_mode,
        created_at=created_at,
        proof_hash=hashlib.sha256(canonical).hexdigest(),
        executable=False,
    )
