"""Deny-by-default network egress policy.

Phase 7 intentionally does not pretend that a Docker bridge network is a
domain allowlist. Strong domain-level egress requires a managed proxy/firewall
boundary. Until such a boundary is configured, AURAGENT runs isolated jobs
with network=none and rejects policies that request external egress.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


class NetworkPolicyError(ValueError):
    """Raised when a requested network policy cannot be safely enforced."""


@dataclass(frozen=True)
class NetworkEgressPolicy:
    enabled: bool = False
    allowed_domains: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    managed_proxy: str | None = None

    def __post_init__(self) -> None:
        normalized_domains = tuple(
            _normalize_domain(value) for value in self.allowed_domains
        )
        object.__setattr__(self, "allowed_domains", normalized_domains)

        for value in self.allowed_cidrs:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise NetworkPolicyError("invalid_allowed_cidr") from exc

        if not self.enabled and (self.allowed_domains or self.allowed_cidrs or self.managed_proxy):
            raise NetworkPolicyError(
                "network_allowlist_present_while_network_disabled"
            )

        if self.enabled and self.managed_proxy is None:
            raise NetworkPolicyError(
                "external_egress_requires_managed_proxy"
            )

    @property
    def docker_network_mode(self) -> str:
        return "none" if not self.enabled else "none"

    def authorize_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False

        hostname = parsed.hostname.rstrip(".").lower()
        if any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in self.allowed_domains
        ):
            return True

        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None

        if address is not None:
            return any(
                address in ipaddress.ip_network(cidr, strict=False)
                for cidr in self.allowed_cidrs
            )

        return False

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "allowed_domains": list(self.allowed_domains),
            "allowed_cidrs": list(self.allowed_cidrs),
            "managed_proxy": self.managed_proxy,
            "enforcement": "managed_proxy" if self.enabled else "docker_network_none",
        }


def _normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain:
        raise NetworkPolicyError("empty_allowed_domain")
    if domain.startswith("*."):
        raise NetworkPolicyError(
            "wildcard_domains_must_be_expressed_as_base_domain"
        )
    if "/" in domain or any(character.isspace() for character in domain):
        raise NetworkPolicyError("invalid_allowed_domain")
    return domain
