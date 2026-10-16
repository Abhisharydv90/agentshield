"""Validated AURAGENT agent manifest contract."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AgentManifest(BaseModel):
    runtime: str = Field(min_length=1, max_length=64)
    entrypoint: str = Field(min_length=1, max_length=256)
    model: str | None = Field(default=None, max_length=160)
    tools: list[str] = Field(default_factory=list, max_length=100)
    environment: dict[str, Any] = Field(default_factory=dict, max_length=100)

    @field_validator("runtime", "entrypoint", "model")
    @classmethod
    def strip_text(cls, value: str | None):
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("manifest_text_required")
        return value

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, value: list[str]) -> list[str]:
        normalized = []
        for item in value:
            item = str(item).strip()
            if item:
                normalized.append(item)
        return list(dict.fromkeys(normalized))

    def bounded_dict(self) -> dict[str, Any]:
        value = self.model_dump(exclude_none=True)
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise ValueError("agent_manifest_too_large")
        return value
