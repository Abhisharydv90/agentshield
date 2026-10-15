"""Composable health/degradation evaluation for scaled deployments."""

from __future__ import annotations

from .contracts import HealthSnapshot, HealthStatus


def evaluate_health(
    *,
    region: str,
    worker_id: str,
    active_leases: int,
    queue_depth: int,
    event_lag: int,
    max_queue_depth: int = 1000,
    max_event_lag: int = 500,
) -> HealthSnapshot:
    if active_leases < 0 or queue_depth < 0 or event_lag < 0:
        raise ValueError("health counters cannot be negative")

    if queue_depth > max_queue_depth * 2 or event_lag > max_event_lag * 2:
        status = HealthStatus.UNAVAILABLE
    elif queue_depth > max_queue_depth or event_lag > max_event_lag:
        status = HealthStatus.DEGRADED
    else:
        status = HealthStatus.HEALTHY

    return HealthSnapshot(
        status=status,
        region=region,
        worker_id=worker_id,
        active_leases=active_leases,
        queue_depth=queue_depth,
        event_lag=event_lag,
    )
