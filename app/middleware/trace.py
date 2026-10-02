import re
import uuid
from fastapi import Request


_TRACE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def get_trace_id(request: Request) -> str:
    """Return a bounded, canonical request trace identifier.

    Caller-supplied IDs are accepted only when they match the safe transport
    format. Otherwise a fresh UUID is generated, preventing arbitrary input
    from becoming a log/audit/Redis correlation key.
    """
    candidate = request.headers.get("X-Trace-Id", "").strip()
    if candidate and _TRACE_RE.fullmatch(candidate):
        return candidate
    return str(uuid.uuid4())
