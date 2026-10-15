"""Region routing and fail-closed region selection."""

from __future__ import annotations

from .contracts import RegionDescriptor


class RegionRoutingError(ValueError):
    pass


def select_region(
    regions: list[RegionDescriptor],
    *,
    preferred: str | None = None,
) -> RegionDescriptor:
    active = [region for region in regions if region.active]
    if not active:
        raise RegionRoutingError("no active region is available")

    if preferred:
        for region in active:
            if region.region == preferred:
                return region

    return sorted(
        active,
        key=lambda item: (item.priority, item.region),
    )[0]


def validate_region_set(regions: list[RegionDescriptor]) -> None:
    if not regions:
        raise RegionRoutingError("at least one region is required")

    names = [region.region.casefold() for region in regions]
    if len(names) != len(set(names)):
        raise RegionRoutingError("duplicate regions are forbidden")

    control_plane = [region for region in regions if region.control_plane_region]
    if len(control_plane) != 1:
        raise RegionRoutingError(
            "exactly one control-plane region must be declared"
        )