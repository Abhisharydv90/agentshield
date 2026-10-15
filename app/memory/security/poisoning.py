"""Heuristics for persistent memory/context poisoning.

This detector is deliberately advisory at the semantic layer but the default
write policy is fail-closed: suspicious content is rejected unless the caller
explicitly chooses quarantine.  Quarantine never grants the memory authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MemoryPoisoningVerdict:
    score: float
    reasons: tuple[str, ...]
    suspicious: bool
    quarantine_recommended: bool


_PATTERNS: tuple[tuple[str, float], ...] = (
    (r"ignore\s+(all|any|the|previous|prior)\s+(instructions|rules|policies)", 0.45),
    (r"system\s+prompt", 0.25),
    (r"developer\s+message", 0.25),
    (r"reveal\s+(the\s+)?(secret|credential|api\s*key|token)", 0.55),
    (r"send\s+(the\s+)?secret", 0.55),
    (r"disable\s+(security|safety|authorization)", 0.50),
    (r"grant\s+.*permission", 0.35),
    (r"execute\s+(this\s+)?command", 0.30),
    (r"run\s+(this\s+)?shell", 0.35),
    (r"do\s+not\s+tell\s+the\s+user", 0.40),
    (r"bypass\s+(policy|approval|security)", 0.50),
    (r"override\s+(policy|authorization|security)", 0.50),
)


def scan_memory(content: str) -> MemoryPoisoningVerdict:
    text = content.lower()
    score = 0.0
    reasons: list[str] = []

    for pattern, weight in _PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            score += weight
            reasons.append(pattern)

    imperative_lines = sum(
        1
        for line in text.splitlines()
        if re.match(r"^\s*(do|ignore|reveal|send|execute|run|disable|override|bypass)\b", line)
    )
    if imperative_lines >= 3:
        score += min(0.25, imperative_lines * 0.05)
        reasons.append("multiple_imperative_lines")

    score = min(1.0, score)

    return MemoryPoisoningVerdict(
        score=score,
        reasons=tuple(reasons),
        suspicious=score >= 0.35,
        quarantine_recommended=score >= 0.60,
    )
