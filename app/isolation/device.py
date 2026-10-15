"""Explicit device boundary policy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class DevicePolicyError(ValueError):
    """Raised when a requested device is outside the allowlist."""


@dataclass(frozen=True)
class DeviceRequest:
    host_path: str
    permissions: str = "r"

    def validate(self, allowed_paths: Iterable[str]) -> "DeviceRequest":
        if self.permissions not in {"r", "rw", "m", "rwm"}:
            raise DevicePolicyError("invalid_device_permissions")

        requested = str(Path(self.host_path).resolve(strict=False))
        allowed = {
            str(Path(value).resolve(strict=False))
            for value in allowed_paths
        }

        if not allowed:
            raise DevicePolicyError("device_access_denied_by_default")
        if requested not in allowed:
            raise DevicePolicyError("device_outside_allowlist")
        return self

    def docker_arg(self) -> str:
        return f"{self.host_path}:{self.host_path}:{self.permissions}"


@dataclass(frozen=True)
class DevicePolicy:
    allowed_paths: tuple[str, ...] = ()
    requests: tuple[DeviceRequest, ...] = ()

    def validate(self) -> tuple[DeviceRequest, ...]:
        validated = tuple(
            request.validate(self.allowed_paths)
            for request in self.requests
        )
        if len({request.host_path for request in validated}) != len(validated):
            raise DevicePolicyError("duplicate_device_request")
        return validated

    def to_dict(self) -> dict:
        return {
            "allowed_paths": list(self.allowed_paths),
            "requests": [
                {
                    "host_path": request.host_path,
                    "permissions": request.permissions,
                }
                for request in self.requests
            ],
        }


def validate_devices(policy: DevicePolicy) -> tuple[DeviceRequest, ...]:
    return policy.validate()
