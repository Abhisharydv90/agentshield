"""
AURAGENT A2A transport routing.

Phase 3 selects the target and transports the request.

Cryptographic agent identity, delegation, capability attenuation and
non-repudiation are intentionally deferred to Phase 4.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.config import settings


class A2ARouteError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class A2ARoute:
    name: str
    url: str
    timeout_seconds: float = 30.0
    headers: dict[str, str] = field(
        default_factory=dict
    )


class A2ARouter:
    def __init__(self) -> None:
        self._routes: dict[
            str,
            A2ARoute,
        ] = {}

        self._load()

    def _load(self) -> None:
        raw = os.getenv(
            "AURAGENT_A2A_ROUTES"
        )

        if not raw:
            return

        try:
            config = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise A2ARouteError(
                "invalid_AURAGENT_A2A_ROUTES"
            ) from exc

        if not isinstance(
            config,
            dict,
        ):
            raise A2ARouteError(
                "a2a_routes_must_be_object"
            )

        for name, value in config.items():
            if not isinstance(
                value,
                dict,
            ):
                raise A2ARouteError(
                    f"invalid_a2a_route:{name}"
                )

            route = A2ARoute(
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
    ) -> A2ARoute:
        route = self._routes.get(
            name
        )

        if route is None:
            raise A2ARouteError(
                f"a2a_route_not_found:{name}"
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
        tenant_id: str,
        agent_id: str,
        trace_id: str,
        payload,
    ) -> dict:
        route = self.resolve(
            route_name
        )

        envelope = {
            "protocol": "a2a",
            "version": "1",
            "trace_id": trace_id,
            "tenant_id": tenant_id,
            "sender_agent_id": agent_id,
            "payload": payload,
        }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Trace-Id": trace_id,
            **route.headers,
        }

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                route.timeout_seconds
            ),
            follow_redirects=False,
        ) as client:
            try:
                response = await client.post(
                    route.url,
                    json=envelope,
                    headers=headers,
                )
            except httpx.HTTPError as exc:
                raise A2ARouteError(
                    "a2a_upstream_unavailable"
                ) from exc

        if len(
            response.content
        ) > 4 * 1024 * 1024:
            raise A2ARouteError(
                "a2a_response_too_large"
            )

        content_type = response.headers.get(
            "content-type",
            "application/json",
        )

        if content_type.startswith(
            "application/json"
        ):
            try:
                result = response.json()
            except ValueError:
                result = {
                    "raw": response.text[:8192]
                }
        else:
            result = {
                "raw": response.text[:8192]
            }

        return {
            "status_code": response.status_code,
            "route": route.name,
            "result": result,
        }

    @staticmethod
    def _validate(
        route: A2ARoute,
    ) -> None:
        parsed = urlparse(
            route.url
        )

        if parsed.scheme not in {
            "http",
            "https",
        }:
            raise A2ARouteError(
                f"invalid_a2a_scheme:{route.name}"
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
            raise A2ARouteError(
                f"insecure_a2a_route_in_prod:{route.name}"
            )

        if not parsed.netloc:
            raise A2ARouteError(
                f"invalid_a2a_host:{route.name}"
            )


a2a_router = A2ARouter()