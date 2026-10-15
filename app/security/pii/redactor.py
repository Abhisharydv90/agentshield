"""
PII redaction.

Sensitive values are replaced with deterministic placeholders.

Security properties:

- No hard-coded production secret.
- Placeholder MAC is scoped to tenant + trace + original value.
- Development may use an ephemeral process secret.
- Production/staging require the configured SECRET_KEY.
- Raw values are persisted only through the PII vault.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from presidio_analyzer import AnalyzerEngine

from app.config import settings
from app.security.pii.vault import vault


# ============================================================
# Analyzer
# ============================================================


_analyzer = AnalyzerEngine()

_entities = [
    entity.strip()
    for entity
    in settings.PII_ENTITIES.split(",")
    if entity.strip()
]


# ============================================================
# Placeholder secret
# ============================================================


if settings.SECRET_KEY.strip():

    _PII_SECRET = hashlib.sha256(
        (
            "agentshield:pii:v1:"
            + settings.SECRET_KEY
        ).encode(
            "utf-8"
        )
    ).digest()

elif settings.ENV == "dev":

    # Development-only ephemeral key.
    #
    # It intentionally changes between process restarts.
    # This avoids embedding a reusable secret in source code.
    _PII_SECRET = secrets.token_bytes(
        32
    )

else:

    raise RuntimeError(
        "SECRET_KEY must be configured "
        "before PII protection can run "
        "outside development."
    )


# ============================================================
# Placeholder
# ============================================================


def _make_placeholder(
    kind: str,
    value: str,
    trace_id: str,
    tenant: str,
) -> str:
    """
    Create a trace + tenant scoped HMAC placeholder.
    """

    message = (
        f"v1|{tenant}|"
        f"{trace_id}|"
        f"{kind}|"
        f"{value}"
    )

    mac = hmac.new(
        _PII_SECRET,
        message.encode(
            "utf-8"
        ),
        hashlib.sha256,
    ).hexdigest()

    return (
        f"<{kind.upper()}_"
        f"{mac[:16]}>"
    )


# ============================================================
# Redactor
# ============================================================


class PIIRedactor:

    def __init__(
        self,
        tenant: str = "default",
    ) -> None:

        self.tenant = tenant

    def _redact_string(
        self,
        text: str,
        trace_id: str,
        collected: dict[str, str],
    ) -> str:

        results = _analyzer.analyze(
            text=text,
            language="en",
            entities=_entities,
        )

        if not results:
            return text

        # Work from right to left so replacement does not
        # invalidate Presidio's original offsets.
        for result in sorted(
            results,
            key=lambda item:
                item.start,
            reverse=True,
        ):

            raw = text[
                result.start:
                result.end
            ]

            if not raw.strip():
                continue

            placeholder = (
                _make_placeholder(
                    kind=
                        result.entity_type,
                    value=
                        raw,
                    trace_id=
                        trace_id,
                    tenant=
                        self.tenant,
                )
            )

            collected[
                placeholder
            ] = raw

            text = (
                text[:result.start]
                + placeholder
                + text[result.end:]
            )

        return text

    def _walk(
        self,
        node,
        trace_id: str,
        collected: dict[str, str],
    ):

        if isinstance(
            node,
            str,
        ):

            return self._redact_string(
                node,
                trace_id,
                collected,
            )

        if isinstance(
            node,
            dict,
        ):

            return {
                key:
                    self._walk(
                        value,
                        trace_id,
                        collected,
                    )
                for key, value
                in node.items()
            }

        if isinstance(
            node,
            list,
        ):

            return [
                self._walk(
                    item,
                    trace_id,
                    collected,
                )
                for item in node
            ]

        return node

    async def redact(
        self,
        body: dict,
        trace_id: str,
    ) -> tuple[
        dict,
        dict[str, str],
    ]:
        """
        Return:

            redacted_body
            placeholder_map

        The raw map is stored in the secure vault.

        If the vault is unavailable, this function raises rather
        than silently returning unprotected PII.
        """

        collected: dict[
            str,
            str,
        ] = {}

        redacted = self._walk(
            body,
            trace_id,
            collected,
        )

        if collected:

            await vault.store(
                trace_id=
                    trace_id,
                tenant=
                    self.tenant,
                mapping=
                    collected,
            )

        return (
            redacted,
            collected,
        )


# ============================================================
# Factory
# ============================================================


def get_redactor(
    tenant: str = "default",
) -> PIIRedactor:

    return PIIRedactor(
        tenant=tenant
    )