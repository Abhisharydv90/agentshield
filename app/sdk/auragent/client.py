"""Minimal Python SDK request-construction surface.

Authentication, authority and tool execution remain server-side.
"""

from __future__ import annotations

from typing import Any, Mapping


class AURAGENTClientError(RuntimeError):
    pass


class AURAGENTClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("AURAGENT SDK base_url must use HTTPS")
        if timeout <= 0 or timeout > 30:
            raise ValueError("timeout must be between 0 and 30 seconds")

        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def build_request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not path.startswith("/"):
            raise ValueError("SDK paths must start with '/'")
        if ".." in path:
            raise ValueError("path traversal is forbidden")

        return {
            "url": f"{self.base_url}{path}",
            "method": method.upper(),
            "headers": self._headers(),
            "body": dict(body) if body is not None else None,
            "timeout": self.timeout,
        }
