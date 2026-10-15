"""AURAGENT Phase 7 Isolation Fabric API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.isolation.device import DevicePolicy, DeviceRequest
from app.isolation.filesystem.mounts import MountSpec
from app.isolation.network.egress import NetworkEgressPolicy
from app.isolation.policy import (
    IsolationBackend,
    IsolationMode,
    IsolationPolicy,
)
from app.isolation.quotas import ResourceQuota
from app.isolation.runner import (
    IsolationDeniedError,
    IsolationExecutionError,
    IsolationExecutionRequest,
    get_isolation_runner,
)
from app.security.context import SecurityContext
from app.security.kernel import SecurityKernel


router = APIRouter(prefix="/v1/isolation", tags=["isolation"])


class MountInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_path: str
    container_path: str
    read_only: bool = True


class DeviceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_path: str
    permissions: str = "r"


class NetworkInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    managed_proxy: str | None = None


class QuotaInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu_cores: float = Field(default=1.0, ge=0.1, le=64.0)
    memory_mb: int = Field(default=512, ge=64, le=131_072)
    timeout_seconds: int = Field(default=60, ge=1, le=86_400)
    pids_limit: int = Field(default=128, ge=16, le=65_536)
    max_output_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=64 * 1_024 * 1_024,
    )


class IsolationPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(default="default", min_length=1, max_length=100)
    backend: IsolationBackend = IsolationBackend.DOCKER
    mode: IsolationMode = IsolationMode.CONTAINER
    image: str = Field(default="python:3.12-slim", min_length=1, max_length=300)
    working_dir: str = Field(default="/workspace", min_length=1, max_length=200)
    user: str = Field(default="65532:65532", min_length=1, max_length=64)
    environment: dict[str, str] = Field(default_factory=dict)
    mounts: list[MountInput] = Field(default_factory=list)
    allowed_host_roots: list[str] = Field(default_factory=list)
    network: NetworkInput = Field(default_factory=NetworkInput)
    devices: list[DeviceInput] = Field(default_factory=list)
    quota: QuotaInput = Field(default_factory=QuotaInput)
    allow_shell: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("environment")
    @classmethod
    def limit_environment_count(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 64:
            raise ValueError("too_many_environment_variables")
        return value


class IsolationRunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: list[str] = Field(min_length=1, max_length=64)
    policy: IsolationPolicyInput = Field(default_factory=IsolationPolicyInput)
    trace_id: str | None = Field(default=None, max_length=128)


def _security_context(request: Request) -> SecurityContext:
    existing = getattr(request.state, "security_context", None)
    if isinstance(existing, SecurityContext):
        return existing

    tenant = getattr(request.state, "tenant", None)
    agent = getattr(request.state, "agent", None)
    if tenant is None or agent is None:
        raise HTTPException(status_code=403, detail="agent_identity_required")
    if agent.status != "active":
        raise HTTPException(status_code=403, detail="agent_inactive")

    authority = SecurityKernel.agent_base_authority(agent)
    context = SecurityContext(
        tenant_id=tenant.tenant_id,
        agent_id=agent.agent_id,
        trace_id=getattr(request.state, "trace_id", ""),
        capabilities=frozenset(agent.scopes or []),
        authority=authority,
        policy_hash="legacy_authenticated_agent",
        authority_token_hash=None,
        provenance={
            "source": "authenticated_agent",
            "isolation_phase": 7,
        },
    )
    request.state.security_context = context
    return context


def _to_policy(body: IsolationPolicyInput) -> IsolationPolicy:
    return IsolationPolicy(
        name=body.name,
        backend=body.backend,
        mode=body.mode,
        image=body.image,
        working_dir=body.working_dir,
        user=body.user,
        environment=dict(body.environment),
        mounts=tuple(
            MountSpec(
                host_path=item.host_path,
                container_path=item.container_path,
                read_only=item.read_only,
            )
            for item in body.mounts
        ),
        allowed_host_roots=tuple(body.allowed_host_roots),
        network=NetworkEgressPolicy(
            enabled=body.network.enabled,
            allowed_domains=tuple(body.network.allowed_domains),
            allowed_cidrs=tuple(body.network.allowed_cidrs),
            managed_proxy=body.network.managed_proxy,
        ),
        devices=DevicePolicy(
            allowed_paths=tuple(item.host_path for item in body.devices),
            requests=tuple(
                DeviceRequest(
                    host_path=item.host_path,
                    permissions=item.permissions,
                )
                for item in body.devices
            ),
        ),
        quota=ResourceQuota(
            cpu_cores=body.quota.cpu_cores,
            memory_mb=body.quota.memory_mb,
            timeout_seconds=body.quota.timeout_seconds,
            pids_limit=body.quota.pids_limit,
            max_output_bytes=body.quota.max_output_bytes,
        ),
        allow_shell=body.allow_shell,
        metadata=dict(body.metadata),
    )


def _to_request(body: IsolationRunInput) -> IsolationExecutionRequest:
    return IsolationExecutionRequest(
        command=tuple(body.command),
        policy=_to_policy(body.policy),
        trace_id=body.trace_id,
    )


@router.get("/templates")
async def list_templates() -> dict[str, Any]:
    from app.isolation.policy import get_environment_templates

    return {"templates": [template.to_dict() for template in get_environment_templates()]}


@router.post("/validate")
async def validate_policy(request: Request, body: IsolationRunInput) -> dict[str, Any]:
    context = _security_context(request)
    try:
        execution_request = _to_request(body)
        return await get_isolation_runner().validate(context, execution_request)
    except IsolationDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (ValueError, IsolationExecutionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/run")
async def run_isolated(request: Request, body: IsolationRunInput) -> dict[str, Any]:
    context = _security_context(request)
    try:
        execution_request = _to_request(body)
        result = await get_isolation_runner().run(context, execution_request)
        return result.to_dict()
    except IsolationDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (ValueError, IsolationExecutionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/runs/{execution_id}")
async def get_run(execution_id: str) -> dict[str, Any]:
    result = await get_isolation_runner().get(execution_id)
    if result is None:
        raise HTTPException(status_code=404, detail="isolation_run_not_found")
    return result.to_dict()


@router.post("/runs/{execution_id}/stop")
async def stop_run(execution_id: str) -> dict[str, Any]:
    stopped = await get_isolation_runner().stop(execution_id)
    if not stopped:
        raise HTTPException(status_code=404, detail="isolation_run_not_active")
    return {"execution_id": execution_id, "stopped": True}
