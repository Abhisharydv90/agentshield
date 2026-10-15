"""SDK metadata and semantic API compatibility rules."""

from __future__ import annotations

import re

from .contracts import CompatibilityResult, SDKDescriptor


_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _parse(version: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(version.strip())
    if not match:
        raise ValueError("version must use MAJOR.MINOR.PATCH")
    return tuple(int(part) for part in match.groups())


def check_api_compatibility(
    *,
    current_api_version: str,
    sdk: SDKDescriptor,
) -> CompatibilityResult:
    current = _parse(current_api_version)
    minimum = _parse(sdk.minimum_api_version)

    compatible = current[0] == minimum[0] and current >= minimum
    message = (
        "SDK is compatible with this API major version"
        if compatible
        else "SDK requires a different or newer API major version"
    )
    return CompatibilityResult(
        compatible=compatible,
        api_version=current_api_version,
        required_minimum=sdk.minimum_api_version,
        message=message,
    )
