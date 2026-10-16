"""
AURAGENT MCP transport routing.

Phase 3 owns route selection/transport.

Actual MCP tool/resource/session semantics belong to Phase 5.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.gateway.routing.transport_security import authorize_external_transport
from app.tools.contracts import ToolKind


class MCPRouteError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class MCPRoute:
    name: str
    url: str
    timeout_seconds: float = 30.0
    headers: dict[str, str] = field(
        default_factory=dict
    )


class MCPRouter:
    def __init__(self) -> None:
        self._routes: dict[
            str,
            MCPRoute,
        ] = {}

        self._load()

    def _load(self) -> None:
        raw = os.getenv(
            "AURAGENT_MCP_ROUTES"
        )

        if not raw:
            return

        try:
            config = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MCPRouteError(
                "invalid_AURAGENT_MCP_ROUTES"
            ) from exc

        if not isinstance(
            config,
            dict,
        ):
            raise MCPRouteError(
                "mcp_routes_must_be_object"
            )

        for name, value in config.items():
            if not isinstance(
                value,
                dict,
            ):
                raise MCPRouteError(
                    f"invalid_mcp_route:{name}"
                )

            route = MCPRoute(
                name=name,
                url=str(
                    value["url"]
                ),
                timeout_seconds=float(
                    value.get(
                        "timeout_seconds",
                        30,
                    )
                ),
                headers={
                    str(k): str(v)
                    for k, v
                    in dict(
                        value.get(
                            "headers",
                            {},
                        )
                    ).items()
                },
            )

            self._validate(
                route
            )

            self._routes[
                name
            ] = route

    def resolve(
        self,
        name: str,
    ) -> MCPRoute:
        route = self._routes.get(
            name
        )

        if route is None:
            raise MCPRouteError(
                f"mcp_route_not_found:{name}"
            )

        return route

    def names(self) -> list[str]:
        return sorted(
            self._routes
        )

    async def dispatch(
        self,
        *,
        route_name: str,
        trace_id: str,
        tenant_id: str,
        agent_id: str,
        agent_scopes,
        payload,
    ) -> dict:
        route = self.resolve(
            route_name
        )

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Trace-Id": trace_id,
            "X-AURAGENT-Tenant": tenant_id,
            "X-AURAGENT-Agent": agent_id,
            **route.headers,
        }

        async def send():
            timeout = httpx.Timeout(route.timeout_seconds)
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
            ) as client:
                try:
                    response = await client.post(
                        route.url,
                        json=payload,
                        headers=headers,
                    )
                except httpx.HTTPError:
                    return {
                        "status_code": 502,
                        "route": route.name,
                        "result": {"error": "mcp_upstream_unavailable"},
                    }

            if len(response.content) > 4 * 1024 * 1024:
                raise MCPRouteError("mcp_response_too_large")

            content_type = response.headers.get("content-type", "application/json")
            if content_type.startswith("application/json"):
                try:
                    result = response.json()
                except ValueError:
                    result = {"raw": response.text[:8192]}
            else:
                result = {"raw": response.text[:8192]}

            return {
                "status_code": response.status_code,
                "route": route.name,
                "result": result,
            }

        authorization = await authorize_external_transport(
            protocol="mcp",
            tool_name=f"gateway.mcp.{route.name}",
            route_name=route.name,
            route_url=route.url,
            tenant_id=uuid.UUID(tenant_id),
            agent_id=uuid.UUID(agent_id),
            agent_scopes=agent_scopes,
            trace_id=trace_id,
            payload=payload,
            kind=ToolKind.MCP,
            send=send,
        )

        if authorization.decision == "allow":
            return dict(authorization.value)

        if authorization.decision == "error":
            raise MCPRouteError("mcp_transport_execution_failed")

        return {
            "status_code": 403,
            "route": route.name,
            "error": authorization.error_code or "authorization_denied",
            "reason": authorization.reason,
            "proof": authorization.proof,
        }

    @staticmethod
    def _validate(
        route: MCPRoute,
    ) -> None:
        parsed = urlparse(
            route.url
        )

        if parsed.scheme not in {
            "http",
            "https",
        }:
            raise MCPRouteError(
                f"invalid_mcp_scheme:{route.name}"
            )

        environment = str(
            getattr(
                settings,
                "ENV",
                "dev",
            )
        ).lower()

        if (
            environment == "prod"
            and parsed.scheme != "https"
        ):
            raise MCPRouteError(
                f"insecure_mcp_route_in_prod:{route.name}"
            )

        if not parsed.netloc:
            raise MCPRouteError(
                f"invalid_mcp_host:{route.name}"
            )


mcp_router = MCPRouter()