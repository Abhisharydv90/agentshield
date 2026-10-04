"""Cryptographic runtime binding primitives for AgentShield."""

from __future__ import annotations

import uuid
from typing import Iterable

from app.policy.dsl import Policy
from app.security.evidence.hashing import fingerprint_evidence


BINDING_SCHEMA_VERSION = "1"
UNBOUND_HASH = "0" * 64


def policy_snapshot(policy: Policy) -> dict:
    """Return the canonical semantic policy snapshot that is hashed."""
    return {
        "schema_version": BINDING_SCHEMA_VERSION,
        "name": policy.name,
        "version": policy.version,
        "default": policy.default,
        "rules": [rule.model_dump(mode="json") for rule in policy.rules],
        "notes": policy.notes,
    }


def policy_snapshot_hash(policy: Policy) -> str:
    """Hash the effective runtime policy content."""
    return fingerprint_evidence(policy_snapshot(policy))


def capability_snapshot(
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    status: str,
    scopes: Iterable[str],
) -> dict:
    """Return the canonical identity/capability state used for hashing."""
    return {
        "schema_version": BINDING_SCHEMA_VERSION,
        "tenant_id": str(tenant_id),
        "agent_id": str(agent_id),
        "status": str(status),
        "scopes": sorted(
            {str(scope).strip() for scope in scopes if str(scope).strip()}
        ),
    }


def capability_snapshot_hash(
    *,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    status: str,
    scopes: Iterable[str],
) -> str:
    """Hash the complete runtime capability snapshot."""
    return fingerprint_evidence(
        capability_snapshot(
            tenant_id=tenant_id,
            agent_id=agent_id,
            status=status,
            scopes=scopes,
        )
    )


def decision_snapshot_hash(
    *,
    action_fingerprint: str,
    policy_hash: str,
    capability_snapshot_hash: str,
    decision: str,
    reason: str,
    missing_capabilities: Iterable[str] = (),
) -> str:
    """Hash the deterministic decision context."""
    return fingerprint_evidence(
        {
            "schema_version": BINDING_SCHEMA_VERSION,
            "action_fingerprint": action_fingerprint,
            "policy_hash": policy_hash,
            "capability_snapshot_hash": capability_snapshot_hash,
            "decision": str(decision),
            "reason": str(reason),
            "missing_capabilities": sorted(
                {str(item) for item in missing_capabilities}
            ),
        }
    )


def approval_decision_hash(
    *,
    action_fingerprint: str,
    policy_hash: str,
    capability_snapshot_hash: str,
) -> str:
    """Hash the approval-required decision context."""
    return decision_snapshot_hash(
        action_fingerprint=action_fingerprint,
        policy_hash=policy_hash,
        capability_snapshot_hash=capability_snapshot_hash,
        decision="approval_required",
        reason="human_approval_required",
    )
