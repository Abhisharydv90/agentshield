"""Resource ceilings for isolated execution.

The quota object is deliberately backend-neutral. Docker enforces the CPU,
memory and PID limits; the runner enforces wall-clock and captured-output
ceilings. The values are bounded again by a server-side Phase 7 ceiling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class QuotaError(ValueError):
    """Raised when an isolation quota is outside a safe range."""


@dataclass(frozen=True)
class ResourceQuota:
    cpu_cores: float = 1.0
    memory_mb: int = 512
    timeout_seconds: int = 60
    pids_limit: int = 128
    max_output_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if not 0.1 <= self.cpu_cores <= 64.0:
            raise QuotaError("cpu_cores must be between 0.1 and 64")
        if not 64 <= self.memory_mb <= 131_072:
            raise QuotaError("memory_mb must be between 64 and 131072")
        if not 1 <= self.timeout_seconds <= 86_400:
            raise QuotaError("timeout_seconds must be between 1 and 86400")
        if not 16 <= self.pids_limit <= 65_536:
            raise QuotaError("pids_limit must be between 16 and 65536")
        if not 1_024 <= self.max_output_bytes <= 64 * 1_024 * 1_024:
            raise QuotaError("max_output_bytes must be between 1 KiB and 64 MiB")

    def ensure_within(self, ceiling: "ResourceQuota") -> None:
        if self.cpu_cores > ceiling.cpu_cores:
            raise QuotaError("cpu_quota_exceeds_server_ceiling")
        if self.memory_mb > ceiling.memory_mb:
            raise QuotaError("memory_quota_exceeds_server_ceiling")
        if self.timeout_seconds > ceiling.timeout_seconds:
            raise QuotaError("timeout_exceeds_server_ceiling")
        if self.pids_limit > ceiling.pids_limit:
            raise QuotaError("pid_quota_exceeds_server_ceiling")
        if self.max_output_bytes > ceiling.max_output_bytes:
            raise QuotaError("output_quota_exceeds_server_ceiling")

    def docker_args(self) -> list[str]:
        return [
            "--cpus",
            str(self.cpu_cores),
            "--memory",
            f"{self.memory_mb}m",
            "--pids-limit",
            str(self.pids_limit),
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_cores": self.cpu_cores,
            "memory_mb": self.memory_mb,
            "timeout_seconds": self.timeout_seconds,
            "pids_limit": self.pids_limit,
            "max_output_bytes": self.max_output_bytes,
        }
