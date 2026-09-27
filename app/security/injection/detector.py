import re
from dataclasses import dataclass
from app.security.injection.unicode import has_smuggling, normalize

# More flexible regex patterns to catch common variations
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

async def scan_inbound(body: dict, trace_id: str, tenant: str = "default") -> InjectionVerdict:
    text = _flatten(body)
    normalized = normalize(text)

    # Stage 1: Signature matching
    for pat in SUSPICIOUS:
        if pat.search(normalized):
            return InjectionVerdict(True, f"signature:{pat.pattern[:32]}", 1.0, "signature")

    # Stage 2: Unicode smuggling (checked on raw text)
    if has_smuggling(text):
        return InjectionVerdict(True, "unicode_smuggling", 0.9, "unicode")

    return InjectionVerdict(False, "clean", 0.0, "clean")

def _flatten(body: dict) -> str:
    parts = []
    for m in body.get("messages", []):
        c = m.get("content", "")
        if isinstance(c, str): 
            parts.append(c)
        elif isinstance(c, list):
            for p in c:
                if isinstance(p, dict) and p.get("type") == "text":
                    parts.append(p.get("text", ""))
    return "\n".join(parts)