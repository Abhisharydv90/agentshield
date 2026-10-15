"""Lifecycle coordinator for isolation backends."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.isolation.container.backend import (
    ContainerConfig,
    ContainerRunResult,
    DockerContainerBackend,
    ProcessIsolationBackend,
)


@dataclass(frozen=True)
class BackendCapabilities:
    name: str
    available: bool
    strong_isolation: bool
    supports_managed_egress: bool


class ContainerLifecycle:
    def __init__(self) -> None:
        self.backends = {
            "docker": DockerContainerBackend(),
            "process": ProcessIsolationBackend(),
        }

    def capabilities(self) -> tuple[BackendCapabilities, ...]:
        return tuple(
            BackendCapabilities(
                name=name,
                available=backend.available(),
                strong_isolation=backend.strong_isolation,
                supports_managed_egress=backend.supports_managed_egress,
            )
            for name, backend in self.backends.items()
        )

    def run(
        self,
        *,
        backend_name: str,
        execution_id: str,
        config: ContainerConfig,
    ) -> ContainerRunResult:
        backend = self.backends.get(backend_name)
        if backend is None:
            raise ValueError("unknown_isolation_backend")
        return backend.run(execution_id=execution_id, config=config)

    def stop(self, *, backend_name: str, execution_id: str) -> None:
        backend = self.backends.get(backend_name)
        if backend is None:
            raise ValueError("unknown_isolation_backend")
        backend.stop(execution_id)
