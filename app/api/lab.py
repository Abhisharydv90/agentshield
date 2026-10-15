"""Admin-only Phase 9 Security Lab API.

The API is tenant-scoped and never executes a real exploit. It invokes the
Security Lab's deterministic simulation unless an internal caller supplies a
trusted LabTarget directly.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.lab.orchestrator import LabOrchestrator, LabRunRequest

router = APIRouter(prefix="/v1/lab", tags=["security-lab"])
_orchestrator = LabOrchestrator()


class LabRunBody(BaseModel):
    scenario_ids: list[str] = Field(default_factory=list, max_length=64)
    seed: int = Field(default=0, ge=0, le=2_147_483_647)
    fuzz: bool = False
    fuzz_cases: int = Field(default=100, ge=1, le=2_000)
    labels: list[str] = Field(default_factory=list, max_length=32)


class CorpusAddBody(BaseModel):
    payload: Any
    source: str = Field(default="manual", min_length=1, max_length=64)
    labels: list[str] = Field(default_factory=list, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _admin_tenant(request: Request) -> str:
    tenant = getattr(request.state, "tenant", None)
    user = getattr(request.state, "user", None)
    if tenant is None or user is None:
        raise HTTPException(status_code=403, detail="admin_context_required")
    role = getattr(user, "role", None)
    role_value = getattr(role, "value", role)
    if str(role_value).lower() not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="security_lab_admin_required")
    tenant_id = getattr(tenant, "tenant_id", tenant)
    return str(tenant_id)


@router.get("/scenarios")
async def list_scenarios(request: Request) -> dict[str, Any]:
    _admin_tenant(request)
    return {"scenarios": _orchestrator.list_scenarios(), "schema": "auragent.lab.scenario-catalog.v1"}


@router.post("/run")
async def run_lab(request: Request, body: LabRunBody) -> dict[str, Any]:
    tenant_id = _admin_tenant(request)
    try:
        report = _orchestrator.run(
            tenant_id=tenant_id,
            request=LabRunRequest(
                scenario_ids=tuple(body.scenario_ids),
                seed=body.seed,
                fuzz=body.fuzz,
                fuzz_cases=body.fuzz_cases,
                labels=tuple(body.labels),
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return report.to_dict()


@router.post("/benchmark")
async def benchmark(request: Request) -> dict[str, Any]:
    tenant_id = _admin_tenant(request)
    report = _orchestrator.benchmark(tenant_id=tenant_id)
    return report.to_dict()


@router.get("/runs")
async def list_runs(request: Request, limit: int = 50) -> dict[str, Any]:
    tenant_id = _admin_tenant(request)
    try:
        rows = _orchestrator.list_reports(tenant_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"runs": rows, "count": len(rows)}


@router.get("/runs/{run_id}")
async def get_run(request: Request, run_id: str) -> dict[str, Any]:
    tenant_id = _admin_tenant(request)
    report = _orchestrator.get_report(tenant_id, run_id)
    if report is None:
        raise HTTPException(status_code=404, detail="lab_run_not_found")
    return report.to_dict()


@router.post("/corpus")
async def add_corpus(request: Request, body: CorpusAddBody) -> dict[str, Any]:
    tenant_id = _admin_tenant(request)
    entry = _orchestrator.add_corpus_case(
        tenant_id=tenant_id,
        payload=body.payload,
        source=body.source,
        labels=body.labels,
        metadata=body.metadata,
    )
    return entry.to_dict(redact_payload=False)


@router.get("/corpus")
async def list_corpus(request: Request, limit: int = 100) -> dict[str, Any]:
    tenant_id = _admin_tenant(request)
    try:
        rows = _orchestrator.list_corpus(tenant_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"entries": rows, "count": len(rows)}


@router.get("/status")
async def lab_status(request: Request) -> dict[str, Any]:
    tenant_id = _admin_tenant(request)
    reports = _orchestrator.list_reports(tenant_id, limit=10)
    latest = reports[0] if reports else None
    return {
        "service": "auragent-security-lab",
        "phase": 9,
        "scenario_count": len(_orchestrator.catalog.scenarios),
        "corpus_count": _orchestrator._corpus(tenant_id).count(),
        "run_count": len(_orchestrator._reports(tenant_id)),
        "latest_run": latest,
        "execution_mode": "simulation-default",
    }
