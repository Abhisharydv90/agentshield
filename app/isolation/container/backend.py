"""Container backend adapters.

Docker is the Phase 7 strong-isolation backend. The adapter never invokes a
shell, never auto-pulls images, defaults to a private network, drops all Linux
capabilities, uses a non-root UID and enforces CPU/memory/PID ceilings.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Mapping, Sequence

from app.isolation.filesystem.mounts import MountSpec
from app.isolation.quotas import ResourceQuota


class ContainerBackendError(RuntimeError):
    """Raised for backend availability or execution failures."""


@dataclass(frozen=True)
class ContainerConfig:
    image: str
    command: tuple[str, ...]
    environment: Mapping[str, str]
    working_dir: str
    user: str
    mounts: tuple[MountSpec, ...]
    network_mode: str
    quota: ResourceQuota
    devices: tuple[str, ...]
    read_only_rootfs: bool = True
    no_new_privileges: bool = True
    drop_all_capabilities: bool = True


@dataclass(frozen=True)
class ContainerRunResult:
    container_id: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


class DockerContainerBackend:
    name = "docker"
    strong_isolation = True
    supports_managed_egress = False

    def available(self) -> bool:
        executable = shutil.which("docker")
        if executable is None:
            return False
        try:
            completed = subprocess.run(
                [executable, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0

    def ensure_image(self, image: str) -> None:
        if not self.available():
            raise ContainerBackendError("docker_unavailable")

        executable = shutil.which("docker")
        assert executable is not None

        completed = subprocess.run(
            [executable, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise ContainerBackendError(
                "container_image_not_present;automatic_image_pull_disabled"
            )

    def run(self, *, execution_id: str, config: ContainerConfig) -> ContainerRunResult:
        self.ensure_image(config.image)

        executable = shutil.which("docker")
        assert executable is not None

        args = [
            executable,
            "run",
            "--name",
            _safe_container_name(execution_id),
            "--rm",
            "--network",
            config.network_mode,
            "--read-only",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--init",
        ]

        args.extend(config.quota.docker_args())
        args.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])
        args.extend(["--workdir", config.working_dir])
        args.extend(["--user", config.user])

        for mount in config.mounts:
            args.extend(["--mount", _docker_mount_arg(mount)])

        for device in config.devices:
            args.extend(["--device", device])

        for key, value in sorted(config.environment.items()):
            args.extend(["--env", f"{key}={value}"])

        args.append(config.image)
        args.extend(config.command)

        started = time.monotonic()
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                timeout=config.quota.timeout_seconds,
                check=False,
                shell=False,
                text=False,
                env=_clean_parent_environment(),
            )
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            self.stop(execution_id)
            duration_ms = int((time.monotonic() - started) * 1000)
            stdout = _decode_output(getattr(exc, "stdout", b""))
            stderr = _decode_output(getattr(exc, "stderr", b""))
            return ContainerRunResult(
                container_id=execution_id,
                exit_code=124,
                stdout=stdout,
                stderr=stderr or "container_execution_timeout",
                timed_out=True,
                duration_ms=duration_ms,
            )
        except OSError as exc:
            raise ContainerBackendError("docker_execution_failed") from exc

        duration_ms = int((time.monotonic() - started) * 1000)
        return ContainerRunResult(
            container_id=execution_id,
            exit_code=int(completed.returncode),
            stdout=_decode_output(completed.stdout),
            stderr=_decode_output(completed.stderr),
            timed_out=timed_out,
            duration_ms=duration_ms,
        )

    def stop(self, execution_id: str) -> None:
        executable = shutil.which("docker")
        if executable is None:
            return
        subprocess.run(
            [executable, "rm", "-f", _safe_container_name(execution_id)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )


def _safe_container_name(execution_id: str) -> str:
    safe = "".join(
        character if character.isalnum() else "-"
        for character in execution_id.lower()
    )
    return f"auragent-isolation-{safe[:48]}"


def _docker_mount_arg(mount: MountSpec) -> str:
    mode = "ro" if mount.read_only else "rw"
    return f"type=bind,src={mount.host_path},dst={mount.container_path},readonly" if mode == "ro" else (
        f"type=bind,src={mount.host_path},dst={mount.container_path}"
    )


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")


def _clean_parent_environment() -> dict[str, str]:
    allowed = {
        key: value
        for key, value in os.environ.items()
        if key in {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "HOME",
            "TMP",
            "TEMP",
        }
    }
    return allowed


class ProcessIsolationBackend:
    """Explicit capability boundary for future host-process isolation.

    A host subprocess is not equivalent to a container. Phase 7 therefore
    refuses to execute through this adapter until a platform-specific strong
    isolation mechanism is installed and wired. This prevents a caller from
    accidentally receiving a false security guarantee.
    """

    name = "process"
    strong_isolation = False
    supports_managed_egress = False

    def available(self) -> bool:
        return False

    def run(self, **_: object) -> ContainerRunResult:
        raise ContainerBackendError(
            "strong_process_isolation_backend_not_configured"
        )

    def stop(self, execution_id: str) -> None:
        return None
