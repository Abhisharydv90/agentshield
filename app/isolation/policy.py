"""Isolation policy contracts and safe environment templates."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from app.isolation.device import DevicePolicy
from app.isolation.filesystem.mounts import MountSpec, validate_mounts
from app.isolation.network.egress import NetworkEgressPolicy
from app.isolation.quotas import ResourceQuota


class IsolationPolicyError(ValueError):
    """Raised when an isolation policy cannot be made safe."""


class IsolationBackend(str, Enum):
    DOCKER = "docker"
    PROCESS = "process"


class IsolationMode(str, Enum):
    CONTAINER = "container"
    PROCESS = "process"


@dataclass(frozen=True)
class EnvironmentTemplate:
    name: str
    image: str
    description: str
    default_working_dir: str = "/workspace"
    default_command: tuple[str, ...] = ("/bin/sh",)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "image": self.image,
            "description": self.description,
            "default_working_dir": self.default_working_dir,
            "default_command": list(self.default_command),
        }


_TEMPLATES: dict[str, EnvironmentTemplate] = {
    "minimal-python": EnvironmentTemplate(
        name="minimal-python",
        image="python:3.12-slim",
        description="Small Python execution environment.",
        default_command=("python",),
    ),
    "minimal-node": EnvironmentTemplate(
        name="minimal-node",
        image="node:22-bookworm-slim",
        description="Small Node.js execution environment.",
        default_command=("node",),
    ),
    "minimal-shell": EnvironmentTemplate(
        name="minimal-shell",
        image="debian:bookworm-slim",
        description="Minimal POSIX shell environment.",
        default_command=("/bin/sh",),
    ),
}


_SECRET_ENV_PATTERN = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class IsolationPolicy:
    name: str = "default"
    backend: IsolationBackend = IsolationBackend.DOCKER
    mode: IsolationMode = IsolationMode.CONTAINER
    image: str = "python:3.12-slim"
    working_dir: str = "/workspace"
    user: str = "65532:65532"
    environment: Mapping[str, str] = ()
    mounts: tuple[MountSpec, ...] = ()
    allowed_host_roots: tuple[str, ...] = ()
    network: NetworkEgressPolicy = NetworkEgressPolicy()
    devices: DevicePolicy = DevicePolicy()
    quota: ResourceQuota = ResourceQuota()
    read_only_rootfs: bool = True
    no_new_privileges: bool = True
    drop_all_capabilities: bool = True
    allow_shell: bool = False
    metadata: Mapping[str, str] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise IsolationPolicyError("policy_name_required")
        if not self.image.strip():
            raise IsolationPolicyError("image_required")
        if not self.working_dir.startswith("/"):
            raise IsolationPolicyError("working_dir_must_be_absolute")
        if self.user.strip() in {"0", "root", "0:0"}:
            raise IsolationPolicyError("root_user_forbidden")

        environment = dict(self.environment)
        for key, value in environment.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", str(key)):
                raise IsolationPolicyError("invalid_environment_variable_name")
            if len(str(value)) > 4096:
                raise IsolationPolicyError("environment_value_too_large")
            if _SECRET_ENV_PATTERN.search(str(key)):
                raise IsolationPolicyError(
                    f"secret_material_must_use_phase5_secret_boundary:{key}"
                )
        object.__setattr__(self, "environment", environment)

        metadata = dict(self.metadata)
        object.__setattr__(self, "metadata", metadata)

        if not self.read_only_rootfs:
            raise IsolationPolicyError("read_only_rootfs_is_mandatory")

        if not self.no_new_privileges:
            raise IsolationPolicyError("no_new_privileges_is_mandatory")

        if not self.drop_all_capabilities:
            raise IsolationPolicyError("capability_drop_all_is_mandatory")

        if self.backend == IsolationBackend.DOCKER and self.mode != IsolationMode.CONTAINER:
            raise IsolationPolicyError("docker_backend_requires_container_mode")

        if self.backend == IsolationBackend.PROCESS and self.mode != IsolationMode.PROCESS:
            raise IsolationPolicyError("process_backend_requires_process_mode")

        validate_mounts(
            self.mounts,
            allowed_host_roots=self.allowed_host_roots,
        )
        self.devices.validate()

    def canonical_payload(self) -> dict:
        return {
            "name": self.name,
            "backend": self.backend.value,
            "mode": self.mode.value,
            "image": self.image,
            "working_dir": self.working_dir,
            "user": self.user,
            "environment": dict(sorted(self.environment.items())),
            "mounts": [
                {
                    "host_path": mount.host_path,
                    "container_path": mount.container_path,
                    "read_only": mount.read_only,
                }
                for mount in self.mounts
            ],
            "network": self.network.to_dict(),
            "devices": self.devices.to_dict(),
            "quota": self.quota.to_dict(),
            "read_only_rootfs": self.read_only_rootfs,
            "no_new_privileges": self.no_new_privileges,
            "drop_all_capabilities": self.drop_all_capabilities,
            "allow_shell": self.allow_shell,
            "metadata": dict(sorted(self.metadata.items())),
        }

    def fingerprint(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict:
        payload = self.canonical_payload()
        payload["policy_hash"] = self.fingerprint()
        return payload


def get_environment_templates() -> tuple[EnvironmentTemplate, ...]:
    return tuple(_TEMPLATES.values())


def resolve_template(name: str) -> EnvironmentTemplate:
    try:
        return _TEMPLATES[name]
    except KeyError as exc:
        raise IsolationPolicyError("unknown_environment_template") from exc
