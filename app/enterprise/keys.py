"""Enterprise key-management contracts and rotation bookkeeping."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Protocol

from .contracts import KeyDescriptor, KeyPurpose


class KeyManagementError(RuntimeError):
    pass


class KeyProvider(Protocol):
    def create_key(
        self,
        *,
        organization_id: str,
        purpose: KeyPurpose,
    ) -> KeyDescriptor:
        ...

    def disable_key(self, key_id: str) -> None:
        ...


class InMemoryKeyProvider:
    """Development/reference provider.

    Production enterprise deployments should bind this interface to KMS/HSM
    infrastructure. Raw key bytes are intentionally never represented here.
    """

    def __init__(self) -> None:
        self._keys: dict[str, KeyDescriptor] = {}

    def create_key(
        self,
        *,
        organization_id: str,
        purpose: KeyPurpose,
    ) -> KeyDescriptor:
        seed = (
            f"{organization_id}:{purpose.value}:"
            f"{len(self._keys) + 1}"
        ).encode("utf-8")
        key_id = "key_" + hashlib.sha256(seed).hexdigest()[:24]
        fingerprint = hashlib.sha256(
            (key_id + purpose.value).encode("utf-8")
        ).hexdigest()

        descriptor = KeyDescriptor(
            key_id=key_id,
            organization_id=organization_id,  # pydantic coerces UUID-compatible strings
            purpose=purpose,
            algorithm="external-kms",
            public_material_fingerprint=fingerprint,
            created_at=datetime.now(timezone.utc),
        )
        self._keys[key_id] = descriptor
        return descriptor

    def disable_key(self, key_id: str) -> None:
        current = self._keys.get(key_id)
        if current is None:
            raise KeyManagementError("key not found")
        self._keys[key_id] = current.model_copy(update={"active": False})

    def list_keys(self, organization_id: str) -> list[KeyDescriptor]:
        return [
            descriptor
            for descriptor in self._keys.values()
            if str(descriptor.organization_id) == str(organization_id)
        ]


def rotation_due(
    descriptor: KeyDescriptor,
    *,
    now: datetime,
    max_age_days: int = 365,
) -> bool:
    if not descriptor.active:
        return False
    age_seconds = (now - descriptor.created_at).total_seconds()
    return age_seconds >= max_age_days * 86400


def key_inventory_digest(
    descriptors: list[KeyDescriptor],
) -> str:
    canonical = "\n".join(
        f"{item.key_id}:{item.version}:{item.algorithm}:{item.active}"
        for item in sorted(descriptors, key=lambda item: item.key_id)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
