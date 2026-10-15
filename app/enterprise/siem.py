"""SIEM/SOC export boundary.

Exports contain redacted security metadata and never raw secrets or evaluator
reasoning. Network delivery is deliberately represented as an adapter contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse

from .contracts import SIEMDestination, SIEMEvent, SIEMFormat


class SIEMPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class SIEMBatch:
    destination_id: str
    body: bytes
    content_type: str


def validate_destination(
    destination: SIEMDestination,
) -> SIEMDestination:
    parsed = urlparse(str(destination.endpoint))
    if parsed.scheme != "https":
        raise SIEMPolicyError("SIEM endpoint must use HTTPS")
    if not parsed.hostname:
        raise SIEMPolicyError("SIEM endpoint hostname is required")
    if parsed.username or parsed.password:
        raise SIEMPolicyError("credentials in SIEM URLs are forbidden")
    return destination


def build_batch(
    destination: SIEMDestination,
    events: list[SIEMEvent],
) -> SIEMBatch:
    destination = validate_destination(destination)
    if len(events) > destination.batch_size:
        raise SIEMPolicyError("SIEM batch exceeds configured batch size")

    for event in events:
        if event.organization_id != destination.organization_id:
            raise SIEMPolicyError("cross-tenant SIEM event rejected")

    payloads = [
        event.model_dump(mode="json")
        for event in events
    ]

    if destination.format == SIEMFormat.JSON:
        body = json.dumps(
            payloads,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        content_type = "application/json"
    else:
        lines = []
        for event in payloads:
            lines.append(
                f"CEF:0|AURAGENT|Security|1|{event['event_type']}|"
                f"{event['event_type']}|{event['severity']}|"
                f"outcome={event.get('outcome') or 'unknown'} "
                f"trace={event.get('trace_id') or '-'}"
            )
        body = "\n".join(lines).encode("utf-8")
        content_type = "application/cef"

    if len(body) > 512 * 1024:
        raise SIEMPolicyError("SIEM batch payload exceeds 512 KiB")

    return SIEMBatch(
        destination_id=destination.destination_id,
        body=body,
        content_type=content_type,
    )


def export_contains_only_redacted_keys(event: SIEMEvent) -> bool:
    forbidden = {"secret", "password", "token", "credential", "private_key"}
    keys = {key.casefold() for key in event.redacted_metadata}
    return not any(
        any(fragment in key for fragment in forbidden)
        for key in keys
    )
