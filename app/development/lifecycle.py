"""Agent lifecycle transition rules."""

from __future__ import annotations

from fastapi import HTTPException


VALID_TRANSITIONS: dict[str, set[str]] = {
    "active": {"suspended", "revoked"},
    "suspended": {"active", "revoked"},
    "revoked": set(),
}


def validate_transition(current: str, target: str) -> None:
    if target not in {"active", "suspended", "revoked"}:
        raise HTTPException(status_code=400, detail="invalid_agent_status")
    if target == current:
        return
    if target not in VALID_TRANSITIONS.get(current, set()):
        raise HTTPException(
            status_code=409,
            detail="invalid_agent_lifecycle_transition",
        )
