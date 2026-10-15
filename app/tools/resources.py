"""Resource authorization primitives for the Tool Fabric."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from app.security.delegation.model import AuthorityState


class ResourceAuthorizationError(ValueError):
    """Raised for malformed resource identifiers."""


@dataclass(frozen=True)
class ResourceDecision:
    allowed: bool
    reason: str
    resource: str | None = None


class ResourceAuthorizer:
    """Match requested resources against an authority resource scope.

    Matching is exact by default. A granted value ending in ``/`` is treated
    as a path-prefix boundary, not as a wildcard expression. Wildcard strings
    remain prohibited by the Phase 4 ResourceScope contract.
    """

    @staticmethod
    def _normalize(resource: str) -> str:
        value = str(resource).strip()
        if not value:
            raise ResourceAuthorizationError("empty resource")
        if "*" in value:
            raise ResourceAuthorizationError("wildcard resources are not supported")
        return value

    def allows(self, authority: AuthorityState, requested: str) -> ResourceDecision:
        try:
            resource = self._normalize(requested)
        except ResourceAuthorizationError as exc:
            return ResourceDecision(False, str(exc), requested)

        for granted in authority.resources.values:
            if resource == granted:
                return ResourceDecision(True, "resource_exact_match", resource)
            if granted.endswith("/") and resource.startswith(granted):
                return ResourceDecision(True, "resource_prefix_match", resource)

        return ResourceDecision(False, "resource_outside_authority", resource)

    def allows_any(self, authority: AuthorityState, requested: list[str] | tuple[str, ...]) -> ResourceDecision:
        if not requested:
            return ResourceDecision(False, "resource_required")
        for resource in requested:
            decision = self.allows(authority, resource)
            if decision.allowed:
                return decision
        return ResourceDecision(False, "no_requested_resource_authorized", requested[0])

    @staticmethod
    def network_domain_allowed(authority: AuthorityState, url: str) -> ResourceDecision:
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            return ResourceDecision(False, "invalid_url")
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            return ResourceDecision(False, "invalid_network_target", url)
        host = parsed.hostname.lower().rstrip(".")
        for granted in authority.network_scopes.values:
            value = granted.lower().rstrip(".")
            if host == value or host.endswith("." + value):
                return ResourceDecision(True, "network_scope_match", host)
        return ResourceDecision(False, "network_target_outside_authority", host)
