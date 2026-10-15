"""Safe local simulation of AURAGENT security boundaries.

This is a reference target for validating the lab itself. It deliberately does
not call tools, contact services, inspect credentials, or grant authority.
Real integration tests can provide a target implementing the LabTarget
contract and can route execution through Phase 4/5/7 security boundaries.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.lab.runner import LabCase, LabObservation


_HIGH_RISK_MARKERS = (
    "ignore previous instructions",
    "reveal the secret",
    "bypass approval",
    "elevate capability",
    "use this tool regardless of policy",
)


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{_flatten(k)} {_flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(item) for item in value)
    return str(value)


def _contains_confusable_instruction(text: str) -> bool:
    lower = text.lower()

    if any(marker in lower for marker in _HIGH_RISK_MARKERS):
        return True

    # Actual Cyrillic confusable characters used by the Phase 9 scenarios.
    confusable_chars = {"\u0456", "\u0430"}
    suspicious_words = ("secret", "approval", "tool", "capability")

    return (
        any(char in text for char in confusable_chars)
        and any(word in lower for word in suspicious_words)
    )


def default_security_simulator(case: LabCase) -> LabObservation:
    text = _flatten(case.payload)
    lower = text.lower()

    if case.scenario_id in {"capability-escalation", "authority-laundering", "approval-bypass"}:
        return LabObservation(
            decision="deny",
            reason="authority_conservation_or_approval_boundary",
            authority_granted=False,
            tool_executed=False,
            evidence_root=hashlib.sha256(case.payload_hash.encode()).hexdigest(),
        )

    if case.scenario_id in {"memory-poisoning", "external-content-instruction", "tool-protocol-confusion"}:
        return LabObservation(
            decision="deny",
            reason="untrusted_content_cannot_grant_authority",
            authority_granted=False,
            tool_executed=False,
            evidence_root=hashlib.sha256(case.payload_hash.encode()).hexdigest(),
        )

    if _contains_confusable_instruction(text) or any(marker in lower for marker in _HIGH_RISK_MARKERS):
        return LabObservation(
            decision="deny",
            reason="untrusted_instruction_or_obfuscation",
            authority_granted=False,
            tool_executed=False,
            evidence_root=hashlib.sha256(case.payload_hash.encode()).hexdigest(),
        )

    return LabObservation(
        decision="allow",
        reason="benign_control_case",
        authority_granted=False,
        tool_executed=False,
        evidence_root=hashlib.sha256(case.payload_hash.encode()).hexdigest(),
    )
