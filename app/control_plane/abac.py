"""Deny-by-default ABAC checks for Control Plane resources."""
from __future__ import annotations

from typing import Mapping


class ABACDenied(PermissionError):
    """ABAC authorization failure."""


class ABACAuthorizer:
    def authorize(
        self,
        *,
        principal_role: str,
        resource_type: str,
        action: str,
        attributes: Mapping[str, str],
    ) -> None:
        if principal_role.casefold() not in {"owner", "admin"} and action != "read":
            raise ABACDenied("mutation requires owner/admin")
        if resource_type not in {
            "organization", "project", "configuration", "api_key", "billing",
        }:
            raise ABACDenied("unknown control-plane resource")
        if not action.strip():
            raise ABACDenied("action required")
        if not attributes.get("organization_id"):
            raise ABACDenied("organization scope required")
        if attributes.get("scope_source") not in {"server", "database"}:
            raise ABACDenied("organization scope must be server/database derived")
