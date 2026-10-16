"""Deterministic browser navigation/action policy."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass(frozen=True)
class BrowserPolicyDecision:
    allowed: bool
    reason: str
    normalized_url: str | None = None


@dataclass(frozen=True)
class BrowserPolicy:
    allowed_domains: frozenset[str] = field(default_factory=frozenset)
    blocked_domains: frozenset[str] = field(default_factory=frozenset)
    allow_http: bool = False
    allow_private_ips: bool = False
    allow_downloads: bool = False
    allow_uploads: bool = False
    allow_secret_entry: bool = False
    max_url_length: int = 4096

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_domains", frozenset(
            str(v).strip().lower().lstrip(".")
            for v in self.allowed_domains
            if str(v).strip()
        ))
        object.__setattr__(self, "blocked_domains", frozenset(
            str(v).strip().lower().lstrip(".")
            for v in self.blocked_domains
            if str(v).strip()
        ))
        if self.max_url_length <= 0:
            raise ValueError("max_url_length must be positive")

    @staticmethod
    def _host_matches(host: str, domain: str) -> bool:
        return host == domain or host.endswith("." + domain)

    def authorize_navigation(self, url: str) -> BrowserPolicyDecision:
        if not isinstance(url, str) or not url:
            return BrowserPolicyDecision(False, "url_required")
        if len(url) > self.max_url_length:
            return BrowserPolicyDecision(False, "url_too_long")

        parsed = urlparse(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            return BrowserPolicyDecision(False, "unsupported_url_scheme")
        if parsed.username or parsed.password:
            return BrowserPolicyDecision(False, "userinfo_in_url_forbidden")
        if parsed.scheme == "http" and not self.allow_http:
            return BrowserPolicyDecision(False, "http_navigation_disabled")

        host = parsed.hostname.lower().rstrip(".")
        if host in {"localhost", "localhost.localdomain", "ip6-localhost"}:
            if not self.allow_private_ips:
                return BrowserPolicyDecision(False, "private_or_local_ip_blocked")

        if host in self.blocked_domains or any(
            self._host_matches(host, domain)
            for domain in self.blocked_domains
        ):
            return BrowserPolicyDecision(False, "domain_blocked")

        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                # Accept legacy numeric IPv4 spellings so loopback/private
                # targets cannot bypass the policy via integer/hex forms.
                packed = socket.inet_aton(host)
                ip = ipaddress.ip_address(packed)
            except (OSError, ValueError):
                ip = None

        if (
            ip is not None
            and not self.allow_private_ips
            and (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            )
        ):
            return BrowserPolicyDecision(False, "private_or_local_ip_blocked")

        if self.allowed_domains:
            if not any(self._host_matches(host, domain) for domain in self.allowed_domains):
                return BrowserPolicyDecision(False, "domain_not_allowlisted")

        normalized = parsed._replace(fragment="").geturl()
        return BrowserPolicyDecision(True, "navigation_allowed", normalized)

    def authorize_download(self) -> BrowserPolicyDecision:
        return BrowserPolicyDecision(self.allow_downloads, "download_allowed" if self.allow_downloads else "downloads_disabled")

    def authorize_upload(self) -> BrowserPolicyDecision:
        return BrowserPolicyDecision(self.allow_uploads, "upload_allowed" if self.allow_uploads else "uploads_disabled")

    def authorize_secret_entry(self) -> BrowserPolicyDecision:
        return BrowserPolicyDecision(self.allow_secret_entry, "secret_entry_allowed" if self.allow_secret_entry else "secret_entry_disabled")
