"""Stable contracts for distributed AURAGENT scale primitives."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ScaleLimits(BaseModel):
    """Hard platform bounds for distributed operations."""

    model_config = ConfigDict(extra="forbid")

    max_batch_size: int = Field(default=100, ge=1, le=1000)
    max_partitions: int = Field(default=256, ge=1, le=4096)
    max_events: int = Field(default=1000, ge=1, le=10000)
    max_worker_leases: int = Field(default=1000, ge=1, le=10000)
    lease_seconds: int = Field(default=30, ge=1, le=300)


class RegionDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region: str = Field(min_length=1, max_length=64)
    control_plane_region: bool = False
    active: bool = True
    priority: int = Field(default=100, ge=0, le=1000)
    endpoint: str | None = None


class ShardDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shard_id: int = Field(ge=0)
    total_shards: int = Field(ge=1)
    tenant_bucket: int = Field(ge=0)
    strategy: str = "rendezvous-v1"


class PartitionAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    partition_id: str
    worker_id: str
    lease_token: int = Field(ge=1)
    leased_until: datetime
    region: str
    fencing_epoch: int = Field(ge=0)


class WorkItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    work_id: UUID
    tenant_id: UUID
    partition_key: str
    operation: str
    payload_digest: str = Field(min_length=64, max_length=64)
    created_at: datetime
    attempt: int = Field(default=0, ge=0, le=1000)
    max_attempts: int = Field(default=5, ge=1, le=1000)
    trace_id: str = Field(min_length=1, max_length=128)
    dedupe_key: str = Field(min_length=1, max_length=256)


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    tenant_id: UUID
    topic: str = Field(min_length=1, max_length=128)
    partition_key: str = Field(min_length=1, max_length=256)
    sequence: int = Field(ge=0)
    occurred_at: datetime
    trace_id: str = Field(min_length=1, max_length=128)
    payload_digest: str = Field(min_length=64, max_length=64)
    headers_redacted: dict[str, str] = Field(default_factory=dict)
    schema_version: str = "1"


class IdempotencyKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    namespace: str = Field(min_length=1, max_length=128)
    key: str = Field(min_length=1, max_length=256)
    request_digest: str = Field(min_length=64, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None


class HealthSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: HealthStatus
    region: str
    worker_id: str
    active_leases: int = Field(ge=0)
    queue_depth: int = Field(ge=0)
    event_lag: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = Field(default_factory=dict)
