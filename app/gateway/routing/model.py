"""
AURAGENT model route registry.

The request supplies a logical route name.

It never supplies an arbitrary upstream URL.

Example:

AURAGENT_MODEL_ROUTES='{
  "default": {
    "provider": "openai-compatible",
    "base_url": "https://api.example.com",
    "chat_path": "/v1/chat/completions",
    "api_key_env": "OPENAI_API_KEY"
  }
}'
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from app.config import settings


class ModelRouteError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ModelRoute:
    name: str
    provider: str
    base_url: str
    chat_path: str = "/v1/chat/completions"
    api_key_env: str | None = None
    static_headers: dict[str, str] = field(
        default_factory=dict
    )
    timeout_seconds: float = 60.0

    @property
    def chat_completions_url(self) -> str:
        return urljoin(
            self.base_url.rstrip("/") + "/",
            self.chat_path.lstrip("/"),
        )

    def api_key(self) -> str | None:
        if not self.api_key_env:
            return None

        value = os.getenv(
            self.api_key_env
        )

        if not value:
            raise ModelRouteError(
                f"missing_model_route_secret:{self.name}"
            )

        return value

    def upstream_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            **self.static_headers,
        }

        key = self.api_key()

        if key:
            headers[
                "Authorization"
            ] = f"Bearer {key}"

        return headers


class ModelRouteRegistry:
    """
    Immutable-by-request route resolver.

    Registrations can be changed only by application/configuration
    code, not by an incoming request.
    """

    def __init__(self) -> None:
        self._routes: dict[
            str,
            ModelRoute,
        ] = {}

        self._load_defaults()

    def _load_defaults(self) -> None:
        raw = os.getenv(
            "AURAGENT_MODEL_ROUTES"
        )

        if raw:
            try:
                config = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ModelRouteError(
                    "invalid_AURAGENT_MODEL_ROUTES"
                ) from exc

            if not isinstance(
                config,
                dict,
            ):
                raise ModelRouteError(
                    "model_routes_must_be_object"
                )

            for name, value in config.items():
                self.register_from_mapping(
                    name,
                    value,
                )

        if self._routes:
            return

        # Backward-compatible bridge to the existing AgentShield
        # upstream configuration.
        base_url = getattr(
            settings,
            "UPSTREAM_URL",
            None,
        )

        if base_url:
            self.register(
                ModelRoute(
                    name="default",
                    provider=(
                        os.getenv(
                            "AURAGENT_DEFAULT_MODEL_PROVIDER",
                            "upstream",
                        )
                    ),
                    base_url=str(
                        base_url
                    ),
                    chat_path="/v1/chat/completions",
                    api_key_env=None,
                    static_headers={},
                    timeout_seconds=float(
                        getattr(
                            settings,
                            "UPSTREAM_TIMEOUT",
                            60,
                        )
                    ),
                )
            )

    def register_from_mapping(
        self,
        name: str,
        value: dict,
    ) -> None:
        if not isinstance(
            value,
            dict,
        ):
            raise ModelRouteError(
                f"model_route_invalid:{name}"
            )

        self.register(
            ModelRoute(
                name=name,
                provider=str(
                    value.get(
                        "provider",
                        "unknown",
                    )
                ),
                base_url=str(
                    value["base_url"]
                ),
                chat_path=str(
                    value.get(
                        "chat_path",
                        "/v1/chat/completions",
                    )
                ),
                api_key_env=(
                    str(
                        value["api_key_env"]
                    )
                    if value.get(
                        "api_key_env"
                    )
                    else None
                ),
                static_headers={
                    str(k): str(v)
                    for k, v
                    in dict(
                        value.get(
                            "static_headers",
                            {},
                        )
                    ).items()
                },
                timeout_seconds=float(
                    value.get(
                        "timeout_seconds",
                        60,
                    )
                ),
            )
        )

    def register(
        self,
        route: ModelRoute,
    ) -> None:
        self._validate_route(
            route
        )

        self._routes[
            route.name
        ] = route

    def resolve(
        self,
        name: str,
    ) -> ModelRoute:
        route = self._routes.get(
            name
        )

        if route is None:
            raise ModelRouteError(
                f"model_route_not_found:{name}"
            )

        return route

    def names(self) -> list[str]:
        return sorted(
            self._routes
        )

    @staticmethod
    def _validate_route(
        route: ModelRoute,
    ) -> None:
        if not route.name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", route.name):
            raise ModelRouteError("invalid_model_route_name")
        if not route.provider.strip():
            raise ModelRouteError("invalid_model_route_provider")
        if not 1 <= route.timeout_seconds <= 300:
            raise ModelRouteError(f"invalid_model_route_timeout:{route.name}")
        parsed = urlparse(route.base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ModelRouteError(f"invalid_model_route_url_components:{route.name}")
        path = urlparse(route.chat_path)
        if path.scheme or path.netloc or not route.chat_path.startswith("/") or route.chat_path.startswith("//"):
            raise ModelRouteError(f"invalid_model_route_path:{route.name}")
        reserved = {"authorization", "proxy-authorization", "host", "content-length", "connection", "transfer-encoding"}
        for key, value in route.static_headers.items():
            normalized = key.strip().lower()
            if not normalized or any(ch in key for ch in " \t\r\n:"):
                raise ModelRouteError(f"invalid_model_header_name:{route.name}")
            if normalized in reserved:
                raise ModelRouteError(f"reserved_model_header:{normalized}")
            if "\r" in value or "\n" in value:
                raise ModelRouteError(f"invalid_model_header_value:{route.name}")

        if parsed.scheme not in {
            "http",
            "https",
        }:
            raise ModelRouteError(
                f"invalid_model_route_scheme:{route.name}"
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
            raise ModelRouteError(
                f"insecure_model_route_in_prod:{route.name}"
            )

        if not parsed.netloc:
            raise ModelRouteError(
                f"invalid_model_route_host:{route.name}"
            )

        if not 1 <= route.timeout_seconds <= 300:
            raise ModelRouteError(
                f"invalid_model_route_timeout:{route.name}"
            )


_model_routes = ModelRouteRegistry()


def get_model_router() -> ModelRouteRegistry:
    return _model_routes