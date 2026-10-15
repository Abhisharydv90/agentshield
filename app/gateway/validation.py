"""
AURAGENT Gateway request validation.

The Gateway validates structure and resource limits.

It does NOT decide whether an action is authorized.
Authorization remains the responsibility of the Trust/Security Kernel
and downstream security boundaries.
"""

from __future__ import annotations

import json
import os
import re
from enum import Enum
from typing import Any

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)


# ============================================================
# Limits
# ============================================================

MAX_GATEWAY_PAYLOAD_BYTES = int(
    os.getenv(
        "AURAGENT_GATEWAY_MAX_PAYLOAD_BYTES",
        str(4 * 1024 * 1024),
    )
)

MAX_GATEWAY_METADATA_KEYS = 64

MAX_ROUTE_NAME_LENGTH = 160

MAX_TIMEOUT_SECONDS = 120


# ============================================================
# Target kinds
# ============================================================

class GatewayTargetKind(str, Enum):
    MODEL = "model"
    AGENT = "agent"
    MCP = "mcp"
    A2A = "a2a"


# ============================================================
# Target
# ============================================================

_ROUTE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$"
)


class GatewayTarget(BaseModel):
    """
    Logical gateway target.

    The name identifies a preconfigured route. The request cannot
    supply an arbitrary network URL.
    """

    kind: GatewayTargetKind

    name: str = Field(
        min_length=1,
        max_length=MAX_ROUTE_NAME_LENGTH,
    )

    @field_validator("name")
    @classmethod
    def validate_name(
        cls,
        value: str,
    ) -> str:
        value = value.strip()

        if not value:
            raise ValueError(
                "gateway_target_name_required"
            )

        if not _ROUTE_PATTERN.fullmatch(
            value
        ):
            raise ValueError(
                "gateway_target_name_invalid"
            )

        return value


# ============================================================
# Gateway request
# ============================================================

class GatewayRequest(BaseModel):
    """
    Generic unified Gateway request.
    """

    target: GatewayTarget

    payload: Any = None

    metadata: dict[str, str | int | bool | None] = Field(
        default_factory=dict
    )

    timeout_seconds: int = Field(
        default=60,
        ge=1,
        le=MAX_TIMEOUT_SECONDS,
    )

    @field_validator("metadata")
    @classmethod
    def validate_metadata(
        cls,
        value: dict,
    ) -> dict:
        if len(value) > MAX_GATEWAY_METADATA_KEYS:
            raise ValueError(
                "gateway_metadata_too_large"
            )

        return value

    @field_validator("payload")
    @classmethod
    def validate_payload(
        cls,
        value: Any,
    ) -> Any:
        try:
            encoded = json.dumps(
                value,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
        except Exception as exc:
            raise ValueError(
                "gateway_payload_not_serializable"
            ) from exc

        if len(encoded) > MAX_GATEWAY_PAYLOAD_BYTES:
            raise ValueError(
                "gateway_payload_too_large"
            )

        return value


# ============================================================
# Model-specific request
# ============================================================

class GatewayModelRequest(BaseModel):
    """
    OpenAI-compatible model payload.

    Additional provider-specific fields are accepted.
    """

    model: str | None = Field(
        default=None,
        max_length=160,
    )

    messages: list[Any] | None = None

    stream: bool = False

    class Config:
        extra = "allow"

    @field_validator("model")
    @classmethod
    def validate_model(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError(
                "model_name_empty"
            )

        return value