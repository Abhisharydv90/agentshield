"""Canonical manifest validation and hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .contracts import EcosystemManifest


def canonical_manifest_payload(manifest: EcosystemManifest) -> bytes:
    payload = manifest.model_dump(
        mode="json",
        exclude={"content_sha256"},
    )
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_manifest_hash(manifest: EcosystemManifest) -> str:
    return hashlib.sha256(canonical_manifest_payload(manifest)).hexdigest()


def with_computed_hash(manifest: EcosystemManifest) -> EcosystemManifest:
    return manifest.model_copy(
        update={"content_sha256": compute_manifest_hash(manifest)}
    )


def verify_manifest_hash(manifest: EcosystemManifest) -> bool:
    return compute_manifest_hash(manifest) == manifest.content_sha256


def validate_declared_permissions(manifest: EcosystemManifest) -> None:
    for permission in manifest.permissions:
        value = permission.strip()
        if not value or value.startswith("*"):
            raise ValueError("wildcard ecosystem permissions are forbidden")
        if len(value) > 128:
            raise ValueError("ecosystem permission is too long")

    for capability in manifest.requested_capabilities:
        if not capability.strip():
            raise ValueError("empty capability request is forbidden")
        if capability.casefold() == "authority:grant":
            raise ValueError("ecosystem entries cannot request authority grants")


def verify_manifest(manifest: EcosystemManifest) -> None:
    if not verify_manifest_hash(manifest):
        raise ValueError("ecosystem manifest hash mismatch")
    validate_declared_permissions(manifest)
    if manifest.ecosystem.casefold() != "auragent":
        raise ValueError("manifest belongs to a different ecosystem")


def safe_public_manifest(manifest: EcosystemManifest) -> dict[str, Any]:
    return manifest.model_dump(mode="json", exclude_none=True)
