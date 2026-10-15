"""Stable, redacted Control Plane contracts."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class OrganizationView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    name: str
    status: str
    created_at: datetime | None
    settings_available: bool


class ProjectView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str
    organization_id: UUID
    name: str
    status: str
    description: str
    created_at: datetime | None


class ProjectCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=500)


class ConfigView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    version: str
    values: dict[str, Any]
    mutable_keys: list[str] = Field(default_factory=list)


class ConfigPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: dict[str, Any] = Field(default_factory=dict)


class APIKeyView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str
    organization_id: UUID
    prefix: str
    active: bool
    created_at: datetime | None
    expires_at: datetime | None
    last_used_at: datetime | None


class UsageSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    since: datetime | None
    request_count: int
    blocked_count: int
    approved_count: int
    denied_count: int
    estimated_usage_units: int


class ABACContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    principal_id: str
    principal_type: str
    role: str
    resource_type: str
    resource_id: str
    action: str
    attributes: dict[str, str] = Field(default_factory=dict)
