"""AURAGENT Phase 13 — Scale Fabric."""

from .contracts import (
    EventEnvelope,
    HealthSnapshot,
    IdempotencyKey,
    PartitionAssignment,
    RegionDescriptor,
    ScaleLimits,
    ShardDescriptor,
    WorkItem,
)
from .service import ScaleService

__all__ = [
    "EventEnvelope",
    "HealthSnapshot",
    "IdempotencyKey",
    "PartitionAssignment",
    "RegionDescriptor",
    "ScaleLimits",
    "ShardDescriptor",
    "WorkItem",
    "ScaleService",
]
