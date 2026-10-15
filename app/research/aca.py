"""Authority-Carrying Agent (ACA) conservation invariant."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import AuthorityVector


class AuthorityConservationError(ValueError):
    pass


@dataclass(frozen=True)
class ConservationResult:
    conserved: bool
    violations: tuple[str, ...]


def conservation_check(
    parent: AuthorityVector,
    child: AuthorityVector,
) -> ConservationResult:
    violations: list[str] = []

    checks = (
        ("capabilities", child.capabilities.issubset(parent.capabilities)),
        ("operations", child.operations.issubset(parent.operations)),
        ("resources", child.resources.issubset(parent.resources)),
        ("data_scopes", child.data_scopes.issubset(parent.data_scopes)),
        ("network_scopes", child.network_scopes.issubset(parent.network_scopes)),
    )

    for dimension, valid in checks:
        if not valid:
            violations.append(f"{dimension} increased")

    if child.delegation_depth > parent.delegation_depth:
        violations.append("delegation depth increased")

    if child.risk_ceiling > parent.risk_ceiling:
        violations.append("risk ceiling increased")

    return ConservationResult(
        conserved=not violations,
        violations=tuple(violations),
    )


def assert_conserved(
    parent: AuthorityVector,
    child: AuthorityVector,
) -> None:
    result = conservation_check(parent, child)
    if not result.conserved:
        raise AuthorityConservationError("; ".join(result.violations))


def authority_distance(
    parent: AuthorityVector,
    child: AuthorityVector,
) -> int:
    return sum(
        (
            parent.capabilities != child.capabilities,
            parent.operations != child.operations,
            parent.resources != child.resources,
            parent.data_scopes != child.data_scopes,
            parent.network_scopes != child.network_scopes,
            parent.delegation_depth != child.delegation_depth,
            parent.risk_ceiling != child.risk_ceiling,
        )
    )
