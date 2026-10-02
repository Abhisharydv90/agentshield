import re
from dataclasses import dataclass
from typing import Any

from app.security.injection.unicode import has_smuggling, normalize


SUSPICIOUS = [
    re.compile(r"ignore\s+.*?(instructions|prompts|rules)", re.I),
    re.compile(r"you are now (DAN|developer mode|unrestricted)", re.I),
    re.compile(r"repeat (the )?(system prompt|initial instructions)", re.I),
    re.compile(r"<\s*\|?im_start\|?\s*>", re.I),
    re.compile(r"\bBEGIN\s+(NEW\s+)?SYSTEM\b", re.I),
    re.compile(r"base64[:=]\s*[A-Za-z0-9+/=]{40,}"),
]


@dataclass
class InjectionVerdict:
    blocked: bool
    reason: str
    score: float
    stage: str


async def scan_inbound(
    body: dict,
    trace_id: str,
    tenant: str = "default",
) -> InjectionVerdict:
    # Scan all scalar string content in the request, including system/
    # developer messages, tool definitions, function schemas, and nested
    # metadata. This keeps the detector aligned with the actual attack surface.
    text = _flatten(body)
    normalized = normalize(text)

    for pat in SUSPICIOUS:
        if pat.search(normalized):
            return InjectionVerdict(
                True,
                f"signature:{pat.pattern[:32]}",
                1.0,
                "signature",
            )

    if has_smuggling(text):
        return InjectionVerdict(
            True,
            "unicode_smuggling",
            0.9,
            "unicode",
        )

    return InjectionVerdict(
        False,
        "clean",
        0.0,
        "clean",
    )


def _flatten(body: dict[str, Any]) -> str:
    parts: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                # Keys can themselves carry attacker-controlled instructions.
                walk(str(key))
                walk(value)
            return
        if isinstance(node, list):
            for item in node:
                walk(item)

    walk(body)
    return "\n".join(parts)
