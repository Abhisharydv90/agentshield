"""
Security Decision Engine contracts.

The decision layer is deliberately independent from HTTP.

A caller provides a normalized security action and receives one of:

    ALLOW
    DENY
    APPROVAL_REQUIRED
    SANITIZE
    QUARANTINE

Approval requests are persisted separately so a human decision becomes
an auditable, one-time authorization artifact.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from app.security.evidence.binding import UNBOUND_HASH


# ============================================================
# Decisions
# ============================================================


class SecurityDecision(StrEnum):
    """
    Canonical AgentShield runtime decisions.
    """

    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    SANITIZE = "sanitize"
    QUARANTINE = "quarantine"


class ApprovalState(StrEnum):
    """
    Persisted state of a human approval request.
    """

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


# ============================================================
# Action identity
# ============================================================


def canonicalize_action(
    action: dict[str, Any],
) -> str:
    """
    Convert an action into a deterministic canonical JSON string.

    This representation is used for fingerprinting and replay protection.
    """

    return json.dumps(
        action,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def fingerprint_action(
    action: dict[str, Any],
) -> str:
    """
    Compute a SHA-256 fingerprint of the complete action.

    A fingerprint is intentionally derived from the entire canonical action,
    not only tool name, so changing arguments creates a different identity.
    """

    canonical = canonicalize_action(action)

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def utc_now() -> datetime:
    """
    Return the current timezone-aware UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    )


# ============================================================
# Security action
# ============================================================


class SecurityAction:
    """
    Immutable-in-practice description of a proposed runtime action.

    The action dictionary is intentionally explicit and becomes part of
    the persisted approval record.
    """

    def __init__(
        self,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        trace_id: str,
        tool_name: str,
        operation: str,
        target: str | None = None,
        arguments: dict[str, Any] | None = None,
        capabilities: list[str] | None = None,
        policy_version: str = "unknown",
        provenance: dict[str, Any] | None = None,
        policy_hash: str = UNBOUND_HASH,
        capability_snapshot_hash: str = UNBOUND_HASH,
    ) -> None:

        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.trace_id = trace_id
        self.tool_name = tool_name
        self.operation = operation
        self.target = target
        self.arguments = arguments or {}
        self.capabilities = sorted(
            set(capabilities or [])
        )
        self.policy_version = policy_version
        self.provenance = provenance or {}
        self.policy_hash = policy_hash
        self.capability_snapshot_hash = capability_snapshot_hash

    def to_dict(self) -> dict[str, Any]:
        """
        Return the canonical security action object.
        """

        return {
            "tenant_id": str(
                self.tenant_id
            ),
            "agent_id": str(
                self.agent_id
            ),
            "trace_id": self.trace_id,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "target": self.target,
            "arguments": self.arguments,
            "capabilities": self.capabilities,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "capability_snapshot_hash": self.capability_snapshot_hash,
            "provenance": self.provenance,
        }

    def fingerprint(self) -> str:
        """
        Return the action fingerprint.
        """

        return fingerprint_action(
            self.to_dict()
        )