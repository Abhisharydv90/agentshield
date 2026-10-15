"""Deterministic tenant/partition sharding."""

from __future__ import annotations

import hashlib
from uuid import UUID

from .contracts import ShardDescriptor


class ShardingError(ValueError):
    pass


def _hash(value: str) -> int:
    return int.from_bytes(
        hashlib.sha256(value.encode("utf-8")).digest()[:8],
        "big",
        signed=False,
    )


def shard_for_tenant(
    *,
    tenant_id: UUID,
    total_shards: int,
) -> ShardDescriptor:
    if total_shards < 1 or total_shards > 4096:
        raise ShardingError("total_shards must be between 1 and 4096")

    bucket = _hash(str(tenant_id)) % total_shards
    return ShardDescriptor(
        shard_id=bucket,
        total_shards=total_shards,
        tenant_bucket=bucket,
    )


def partition_for_key(
    *,
    partition_key: str,
    partition_count: int,
) -> int:
    if not partition_key.strip():
        raise ShardingError("partition_key is required")
    if partition_count < 1 or partition_count > 4096:
        raise ShardingError("partition_count must be between 1 and 4096")
    return _hash(partition_key) % partition_count
