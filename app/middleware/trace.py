import uuid
from fastapi import Request

def get_trace_id(request: Request) -> str:
    """Generates or retrieves a trace ID for every request."""
    return request.headers.get("X-Trace-Id", str(uuid.uuid4()))