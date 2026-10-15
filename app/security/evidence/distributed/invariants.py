"""Tenant-safe invariants for distributed evidence writers.

This module is the coordination contract for future multi-worker/multi-region
Evidence Fabric deployments. It does not replace the existing per-tenant
PostgreSQL audit chain. Instead, it defines additional invariants that a
distributed evidence writer must preserve:

- a batch belongs to exactly one tenant;
- sequence numbers are contiguous for one writer stream;
- a later batch must reference the previous root exactly;
- evidence fragments are content-addressed;
- a batch root is deterministic;
- a batch cannot merge fragments from different tenants.

The implementation is backend-neutral and performs no network I/O.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Iterable


class DistributedEvidenceInvariantError(ValueError):
    """Raised when a distributed Evidence Fabric invariant is violated."""


@dataclass(frozen=True)
class EvidenceFragment:
    tenant_id: uuid.UUID
    evidence_id: uuid.UUID
    artifact_hash: str
    sequence: int

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, uuid.UUID):
            raise DistributedEvidenceInvariantError("tenant_id_must_be_uuid")
        if not isinstance(self.evidence_id, uuid.UUID):
            raise DistributedEvidenceInvariantError("evidence_id_must_be_uuid")
        if len(self.artifact_hash) != 64:
            raise DistributedEvidenceInvariantError("artifact_hash_must_be_sha256")
        if not self.artifact_hash.isalnum():
            raise DistributedEvidenceInvariantError("artifact_hash_invalid")
        if self.sequence < 0:
            raise DistributedEvidenceInvariantError("fragment_sequence_negative")

    def canonical(self) -> dict:
        return {
            "tenant_id": str(self.tenant_id),
            "evidence_id": str(self.evidence_id),
            "artifact_hash": self.artifact_hash.lower(),
            "sequence": self.sequence,
        }


@dataclass(frozen=True)
class EvidenceBatch:
    tenant_id: uuid.UUID
    writer_id: str
    sequence: int
    previous_root: str | None
    fragments: tuple[EvidenceFragment, ...]
    batch_root: str

    def __post_init__(self) -> None:
        if not self.writer_id.strip():
            raise DistributedEvidenceInvariantError("writer_id_required")
        if self.sequence < 0:
            raise DistributedEvidenceInvariantError("batch_sequence_negative")
        if not self.fragments:
            raise DistributedEvidenceInvariantError("batch_must_contain_fragment")

        for fragment in self.fragments:
            if fragment.tenant_id != self.tenant_id:
                raise DistributedEvidenceInvariantError("cross_tenant_fragment")
        if self.previous_root is not None and len(self.previous_root) != 64:
            raise DistributedEvidenceInvariantError("previous_root_must_be_sha256")
        if len(self.batch_root) != 64:
            raise DistributedEvidenceInvariantError("batch_root_must_be_sha256")

    def canonical(self) -> dict:
        return {
            "schema": "auragent.distributed-evidence-batch.v1",
            "tenant_id": str(self.tenant_id),
            "writer_id": self.writer_id,
            "sequence": self.sequence,
            "previous_root": self.previous_root,
            "fragments": [
                fragment.canonical()
                for fragment in sorted(
                    self.fragments,
                    key=lambda value: (value.sequence, str(value.evidence_id)),
                )
            ],
        }


def compute_batch_root(
    *,
    tenant_id: uuid.UUID,
    writer_id: str,
    sequence: int,
    previous_root: str | None,
    fragments: Iterable[EvidenceFragment],
) -> str:
    """Compute the deterministic SHA-256 root for one evidence batch."""

    ordered = sorted(
        fragments,
        key=lambda value: (value.sequence, str(value.evidence_id)),
    )
    payload = {
        "schema": "auragent.distributed-evidence-batch.v1",
        "tenant_id": str(tenant_id),
        "writer_id": writer_id,
        "sequence": sequence,
        "previous_root": previous_root,
        "fragments": [fragment.canonical() for fragment in ordered],
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def assert_batch_append(
    *,
    previous_sequence: int | None,
    previous_root: str | None,
    batch: EvidenceBatch,
) -> None:
    """Verify that a batch extends one writer stream without forking."""

    if previous_sequence is None:
        if batch.sequence != 0:
            raise DistributedEvidenceInvariantError(
                "first_batch_sequence_must_be_zero"
            )
        if batch.previous_root is not None:
            raise DistributedEvidenceInvariantError(
                "first_batch_cannot_reference_previous_root"
            )
        return

    if batch.sequence != previous_sequence + 1:
        raise DistributedEvidenceInvariantError("distributed_sequence_gap")

    if previous_root is None or batch.previous_root != previous_root:
        raise DistributedEvidenceInvariantError("distributed_root_link_mismatch")


def verify_batch(batch: EvidenceBatch) -> bool:
    """Recompute and verify a batch root and all tenant bindings."""

    if any(fragment.tenant_id != batch.tenant_id for fragment in batch.fragments):
        raise DistributedEvidenceInvariantError("cross_tenant_fragment")

    expected = compute_batch_root(
        tenant_id=batch.tenant_id,
        writer_id=batch.writer_id,
        sequence=batch.sequence,
        previous_root=batch.previous_root,
        fragments=batch.fragments,
    )
    if expected != batch.batch_root:
        raise DistributedEvidenceInvariantError("distributed_batch_root_mismatch")
    return True
