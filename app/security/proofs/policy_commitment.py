"""Content-addressed policy commitments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from app.security.identity.crypto import canonical_json, sha256_hex


def _policy_payload(policy: Any) -> dict[str, Any]:
    if isinstance(policy, Mapping):
        data = dict(policy)
    elif hasattr(policy, "model_dump"):
        data = dict(policy.model_dump())
    elif hasattr(policy, "dict"):
        data = dict(policy.dict())
    elif hasattr(policy, "__dict__"):
        data = {k: v for k, v in vars(policy).items() if not k.startswith("_")}
    else:
        data = {"value": str(policy)}
    return data


@dataclass(frozen=True)
class PolicyCommitment:
    name: str
    version: str
    content_hash: str
    schema: str = "auragent.policy-commitment.v1"

    @classmethod
    def from_policy(cls, policy: Any, *, name: str | None = None, version: str | None = None) -> "PolicyCommitment":
        payload = _policy_payload(policy)
        resolved_name = str(name if name is not None else payload.get("name", "unknown"))
        resolved_version = str(version if version is not None else payload.get("version", "unknown"))
        canonical_payload = {
            "schema": cls.schema,
            "name": resolved_name,
            "version": resolved_version,
            "content": payload,
        }
        return cls(
            name=resolved_name,
            version=resolved_version,
            content_hash=sha256_hex(canonical_payload),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "name": self.name,
            "version": self.version,
            "content_hash": self.content_hash,
        }
