"""Filesystem boundary validation for isolated execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


class FilesystemPolicyError(ValueError):
    """Raised when a filesystem mount violates the isolation policy."""


@dataclass(frozen=True)
class MountSpec:
    host_path: str
    container_path: str
    read_only: bool = True

    def validate(self, allowed_host_roots: Iterable[str]) -> "MountSpec":
        # Host paths follow the host operating system's path semantics.
        raw_host = Path(self.host_path)

        # Container paths are always POSIX paths, even when AURAGENT is
        # running on Windows and the Docker host uses Windows paths.
        raw_container = PurePosixPath(self.container_path)

        if not raw_host.is_absolute():
            raise FilesystemPolicyError("host_path_must_be_absolute")

        if not raw_container.is_absolute():
            raise FilesystemPolicyError("container_path_must_be_absolute")

        if raw_container == PurePosixPath("/"):
            raise FilesystemPolicyError("container_root_mount_forbidden")

        host = raw_host.resolve(strict=False)

        if not host.exists():
            raise FilesystemPolicyError("host_path_does_not_exist")

        roots = [
            Path(root).resolve(strict=False)
            for root in allowed_host_roots
        ]

        if not roots:
            raise FilesystemPolicyError(
                "host_bind_mounts_require_explicit_allowed_root"
            )

        if not any(_is_within(host, root) for root in roots):
            raise FilesystemPolicyError("host_path_outside_allowed_root")

        return self

    def docker_bind(self) -> str:
        mode = "ro" if self.read_only else "rw"
        return f"{self.host_path}:{self.container_path}:{mode}"


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_mounts(
    mounts: Iterable[MountSpec],
    *,
    allowed_host_roots: Iterable[str],
) -> tuple[MountSpec, ...]:
    validated: list[MountSpec] = []
    seen_destinations: set[str] = set()

    for mount in mounts:
        mount.validate(allowed_host_roots)

        # Container destinations use POSIX semantics independently of the
        # operating system running AURAGENT.
        destination = str(PurePosixPath(mount.container_path))

        if destination in seen_destinations:
            raise FilesystemPolicyError("duplicate_container_mount")

        seen_destinations.add(destination)
        validated.append(mount)

    return tuple(validated)