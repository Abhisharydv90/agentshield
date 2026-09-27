"""
PII Redactor — detects and replaces sensitive entities with reversible placeholders.
Uses Microsoft Presidio for detection, HMAC for tamper-proof placeholder generation.
"""
import hashlib
import hmac
from presidio_analyzer import AnalyzerEngine
from app.config import settings
from app.security.pii.vault import vault

_analyzer = AnalyzerEngine()
_entities = [e.strip() for e in settings.PII_ENTITIES.split(",") if e.strip()]

# Per-tenant HMAC secret — in production this comes from KMS per tenant.
# For now, derive from a base secret. Rotate per environment.
_BASE_SECRET = b"agentshield-dev-secret-rotate-in-prod"


def _make_placeholder(kind: str, value: str, trace_id: str) -> str:
    """Deterministic, non-guessable placeholder scoped to a trace."""
    mac = hmac.new(_BASE_SECRET, f"{trace_id}:{value}".encode(), hashlib.sha256).hexdigest()
    return f"<{kind.upper()}_{mac[:12]}>"


class PIIRedactor:
    def __init__(self, tenant: str = "default"):
        self.tenant = tenant

    def _redact_string(self, text: str, trace_id: str, collected: dict[str, str]) -> str:
        results = _analyzer.analyze(text=text, language="en", entities=_entities)
        if not results:
            return text
        # Sort by start descending so we don't invalidate indices
        for r in sorted(results, key=lambda x: x.start, reverse=True):
            raw = text[r.start:r.end]
            if not raw.strip():
                continue
            placeholder = _make_placeholder(r.entity_type, raw, trace_id)
            collected[placeholder] = raw
            text = text[:r.start] + placeholder + text[r.end:]
        return text

    def _walk(self, node, trace_id: str, collected: dict[str, str]):
        if isinstance(node, str):
            return self._redact_string(node, trace_id, collected)
        if isinstance(node, dict):
            return {k: self._walk(v, trace_id, collected) for k, v in node.items()}
        if isinstance(node, list):
            return [self._walk(v, trace_id, collected) for v in node]
        return node

    async def redact(self, body: dict, trace_id: str) -> tuple[dict, dict[str, str]]:
        """
        Returns (redacted_body, placeholder_map).
        The map is also persisted in the vault for later rehydration.
        """
        collected: dict[str, str] = {}
        redacted = self._walk(body, trace_id, collected)
        if collected:
            await vault.store(trace_id, self.tenant, collected)
        return redacted, collected


# Factory — allows per-tenant redactor instances
def get_redactor(tenant: str = "default") -> PIIRedactor:
    return PIIRedactor(tenant=tenant)