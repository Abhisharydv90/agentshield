"""Explicit Control Plane RBAC."""
from __future__ import annotations
from enum import StrEnum


class ControlPlaneAction(StrEnum):
    READ = "read"
    CONFIGURE = "configure"
    MANAGE_PROJECTS = "manage_projects"
    MANAGE_API_KEYS = "manage_api_keys"
    VIEW_USAGE = "view_usage"


_ROLE_ACTIONS = {
    "owner": set(ControlPlaneAction),
    "admin": set(ControlPlaneAction),
    "member": {ControlPlaneAction.READ},
}


def normalize_role(role: object) -> str:
    return str(getattr(role, "value", role) or "").casefold()


def allowed(role: object, action: ControlPlaneAction) -> bool:
    return action in _ROLE_ACTIONS.get(normalize_role(role), set())


def require(role: object, action: ControlPlaneAction) -> None:
    if not allowed(role, action):
        raise PermissionError(f"role does not permit {action.value}")
