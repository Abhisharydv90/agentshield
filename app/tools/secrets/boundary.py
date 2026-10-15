"""Capability-gated secret access.

Secrets are not part of ToolManifest metadata, logs, decision reasons, proofs,
or tool discovery responses. A caller must explicitly possess ``secret:use``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from app.security.context import SecurityContext


class SecretProvider(Protocol):
    def get(self, name: str) -> str | None: ...


class EnvSecretProvider:
    def get(self, name: str) -> str | None:
        return os.getenv(name)


@dataclass
class SecretLease:
    name: str
    _value: str
    purpose: str
    _revoked: bool = False

    @property
    def value(self) -> str:
        if self._revoked:
            raise RuntimeError("secret_lease_revoked")
        return self._value

    @property
    def redacted(self) -> str:
        return "[REDACTED]"

    def revoke(self) -> None:
        self._revoked = True
        self._value = ""

    def __repr__(self) -> str:
        return f"SecretLease(name={self.name!r}, value='[REDACTED]')"


class SecretBoundary:
    def __init__(
        self,
        provider: SecretProvider | None = None,
        *,
        allowed_names: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.provider = provider or EnvSecretProvider()
        self.allowed_names = frozenset(allowed_names or set())

    def get(
        self,
        name: str,
        context: SecurityContext,
        *,
        purpose: str,
    ) -> SecretLease:
        normalized = str(name).strip()
        if not normalized:
            raise ValueError("secret name is required")
        if "secret:use" not in context.capabilities:
            raise PermissionError("secret_use_capability_required")
        if self.allowed_names and normalized not in self.allowed_names:
            raise PermissionError("secret_not_allowlisted")

        value = self.provider.get(normalized)
        if value is None:
            raise KeyError("secret_not_found")
        return SecretLease(normalized, value, purpose)
