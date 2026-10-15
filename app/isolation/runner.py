"""Phase 7 Isolation Runner — policy-first execution boundary."""

from __future__ import annotations

import asyncio
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.isolation.container.backend import ContainerConfig, ContainerBackendError
from app.isolation.container.lifecycle import ContainerLifecycle
from app.isolation.device import DeviceRequest
from app.isolation.filesystem.mounts import FilesystemPolicyError
from app.isolation.policy import (
    IsolationBackend,
    IsolationMode,
    IsolationPolicy,
)
from app.isolation.quotas import QuotaError, ResourceQuota
from app.security.context import SecurityContext


class IsolationDeniedError(PermissionError):
    """Raised when the Trust Kernel boundary does not authorize execution."""


class IsolationExecutionError(RuntimeError):
    """Raised when execution cannot be safely started."""


@dataclass(frozen=True)
class IsolationExecutionRequest:
    command: tuple[str, ...]
    policy: IsolationPolicy
    trace_id: str | None = None

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("command_required")
        if any(not str(part).strip() for part in self.command):
            raise ValueError("command_arguments_must_not_be_empty")
        if len(self.command) > 64:
            raise ValueError("command_too_long")


@dataclass(frozen=True)
class IsolationExecutionResult:
    execution_id: str
    status: str
    backend: str
    strong_isolation: bool
    exit_code: int | None
    timed_out: bool
    duration_ms: int
    stdout: str
    stderr: str
    policy_hash: str
    trace_id: str | None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "backend": self.backend,
            "strong_isolation": self.strong_isolation,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "policy_hash": self.policy_hash,
            "trace_id": self.trace_id,
            "reason": self.reason,
        }


class IsolationRunner:
    """Single policy enforcement point for isolated execution."""

    SERVER_QUOTA_CEILING = ResourceQuota(
        cpu_cores=8.0,
        memory_mb=16_384,
        timeout_seconds=3_600,
        pids_limit=4_096,
        max_output_bytes=16 * 1_024 * 1_024,
    )

    def __init__(self, lifecycle: ContainerLifecycle | None = None) -> None:
        self.lifecycle = lifecycle or ContainerLifecycle()
        self._history: dict[str, IsolationExecutionResult] = {}
        # Ownership is security state: every execution id is bound to the
        # authenticated tenant + agent that created it.
        self._ownership: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
        # Active executions also retain the selected backend so stop cannot
        # be redirected to an unrelated/default backend.
        self._active: dict[str, tuple[uuid.UUID, uuid.UUID, str]] = {}
        self._lock = asyncio.Lock()

    async def validate(
        self,
        context: SecurityContext,
        request: IsolationExecutionRequest,
    ) -> dict[str, Any]:
        self._authorize_request(context, request)
        backend = self.lifecycle.backends[request.policy.backend.value]

        if not backend.available():
            return {
                "allowed": True,
                "executable": False,
                "reason": "backend_unavailable",
                "backend": backend.name,
                "strong_isolation": backend.strong_isolation,
                "policy_hash": request.policy.fingerprint(),
            }

        return {
            "allowed": True,
            "executable": True,
            "reason": "policy_valid",
            "backend": backend.name,
            "strong_isolation": backend.strong_isolation,
            "policy_hash": request.policy.fingerprint(),
            "quota": request.policy.quota.to_dict(),
        }

    async def run(
        self,
        context: SecurityContext,
        request: IsolationExecutionRequest,
    ) -> IsolationExecutionResult:
        self._authorize_request(context, request)

        policy = request.policy
        policy.quota.ensure_within(self.SERVER_QUOTA_CEILING)

        backend = self.lifecycle.backends.get(policy.backend.value)
        if backend is None:
            raise IsolationExecutionError("unknown_backend")

        if not backend.strong_isolation:
            raise IsolationExecutionError("strong_isolation_backend_required")

        if not backend.available():
            raise IsolationExecutionError("isolation_backend_unavailable")

        if policy.network.enabled:
            if not backend.supports_managed_egress:
                raise IsolationExecutionError(
                    "managed_network_egress_backend_not_configured"
                )

        self._validate_command(request.command, policy)
        execution_id = str(uuid.uuid4())

        config = ContainerConfig(
            image=policy.image,
            command=tuple(request.command),
            environment=dict(policy.environment),
            working_dir=policy.working_dir,
            user=policy.user,
            mounts=tuple(policy.mounts),
            network_mode=policy.network.docker_network_mode,
            quota=policy.quota,
            devices=tuple(request_.docker_arg() for request_ in policy.devices.requests),
            read_only_rootfs=policy.read_only_rootfs,
            no_new_privileges=policy.no_new_privileges,
            drop_all_capabilities=policy.drop_all_capabilities,
        )

        async with self._lock:
            self._active[execution_id] = (
                context.tenant_id,
                context.agent_id,
                policy.backend.value,
            )

        started = time.monotonic()
        try:
            raw = await asyncio.to_thread(
                self.lifecycle.run,
                backend_name=policy.backend.value,
                execution_id=execution_id,
                config=config,
            )
            stdout = raw.stdout
            stderr = raw.stderr

            max_output = policy.quota.max_output_bytes
            stdout = stdout[:max_output]
            stderr = stderr[:max_output]

            status = (
                "timed_out"
                if raw.timed_out
                else "completed"
                if raw.exit_code == 0
                else "failed"
            )
            result = IsolationExecutionResult(
                execution_id=execution_id,
                status=status,
                backend=backend.name,
                strong_isolation=backend.strong_isolation,
                exit_code=raw.exit_code,
                timed_out=raw.timed_out,
                duration_ms=max(
                    raw.duration_ms,
                    int((time.monotonic() - started) * 1000),
                ),
                stdout=stdout,
                stderr=stderr,
                policy_hash=policy.fingerprint(),
                trace_id=request.trace_id or context.trace_id,
            )
        except ContainerBackendError as exc:
            result = IsolationExecutionResult(
                execution_id=execution_id,
                status="failed",
                backend=backend.name,
                strong_isolation=backend.strong_isolation,
                exit_code=None,
                timed_out=False,
                duration_ms=int((time.monotonic() - started) * 1000),
                stdout="",
                stderr="isolation_backend_error",
                policy_hash=policy.fingerprint(),
                trace_id=request.trace_id or context.trace_id,
                reason=str(exc),
            )
        finally:
            async with self._lock:
                self._active.pop(execution_id, None)

        async with self._lock:
            self._history[execution_id] = result
            self._ownership[execution_id] = (
                context.tenant_id,
                context.agent_id,
            )
            if len(self._history) > 2048:
                oldest = next(iter(self._history))
                self._history.pop(oldest, None)
                self._ownership.pop(oldest, None)

        return result

    async def stop(
        self,
        execution_id: str,
        *,
        context: SecurityContext,
    ) -> bool:
        async with self._lock:
            active = self._active.get(execution_id)
            if active is None:
                return False

            owner_tenant_id, owner_agent_id, backend_name = active

            if (
                owner_tenant_id != context.tenant_id
                or owner_agent_id != context.agent_id
            ):
                return False

        await asyncio.to_thread(
            self.lifecycle.stop,
            backend_name=backend_name,
            execution_id=execution_id,
        )
        return True

    async def get(
        self,
        execution_id: str,
        *,
        context: SecurityContext,
    ) -> IsolationExecutionResult | None:
        async with self._lock:
            owner = self._ownership.get(execution_id)
            if owner is None:
                return None

            if owner != (
                context.tenant_id,
                context.agent_id,
            ):
                return None

            return self._history.get(execution_id)

    @staticmethod
    def _authorize_request(
        context: SecurityContext,
        request: IsolationExecutionRequest,
    ) -> None:
        required = {"execute"}
        if request.policy.mode == IsolationMode.PROCESS:
            required.add("process:execute")

        mounts = request.policy.mounts
        if mounts:
            required.add("filesystem:read")
            if any(not mount.read_only for mount in mounts):
                required.add("filesystem:write")

        if request.policy.network.enabled:
            required.add("network:egress")

        if request.policy.devices.requests:
            required.add("device:use")

        missing = required.difference(context.capabilities)
        if missing:
            raise IsolationDeniedError(
                "missing_isolation_capabilities:" + ",".join(sorted(missing))
            )

    @staticmethod
    def _validate_command(
        command: Sequence[str],
        policy: IsolationPolicy,
    ) -> None:
        if any(len(part) > 16_384 for part in command):
            raise IsolationExecutionError("command_argument_too_large")

        if not policy.allow_shell:
            forbidden = {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"}
            executable = os.path.basename(str(command[0])).lower()
            if executable in forbidden:
                raise IsolationExecutionError(
                    "shell_execution_disabled_by_policy"
                )


_GLOBAL_RUNNER: IsolationRunner | None = None


def get_isolation_runner() -> IsolationRunner:
    global _GLOBAL_RUNNER
    if _GLOBAL_RUNNER is None:
        _GLOBAL_RUNNER = IsolationRunner()
    return _GLOBAL_RUNNER
