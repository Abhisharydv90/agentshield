"""Stable, hash-committed Phase 9 security lab reports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.lab.runner import LabCaseResult

REPORT_SCHEMA = "auragent.lab.report.v1"


@dataclass(frozen=True)
class LabFinding:
    finding_id: str
    case_id: str
    scenario_id: str
    severity: str
    category: str
    message: str
    evidence_root: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "scenario_id": self.scenario_id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "evidence_root": self.evidence_root,
        }


@dataclass(frozen=True)
class LabRunReport:
    tenant_id: str
    run_id: str
    schema: str
    started_at: str
    finished_at: str
    seed: int
    labels: tuple[str, ...]
    total_cases: int
    passed: int
    failed: int
    errors: int
    duration_ms: float
    coverage_pct: float
    findings: tuple[LabFinding, ...]
    case_results: tuple[LabCaseResult, ...]
    report_hash: str

    @staticmethod
    def _canonical_without_hash(payload: dict[str, Any]) -> bytes:
        clean = dict(payload)
        clean.pop("report_hash", None)
        return json.dumps(
            clean,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        run_id: str,
        seed: int,
        results: list[LabCaseResult],
        labels: tuple[str, ...] = (),
    ) -> "LabRunReport":
        now = datetime.now(timezone.utc)
        started_at = now.isoformat()
        duration_ms = sum(item.duration_ms for item in results)
        passed = sum(item.status == "pass" for item in results)
        failed = sum(item.status == "fail" for item in results)
        errors = sum(item.status == "error" for item in results)
        total = len(results)
        coverage_pct = round(((passed + failed) / total) * 100.0, 3) if total else 100.0

        findings: list[LabFinding] = []
        for index, result in enumerate(results):
            if result.status == "pass":
                continue
            message = result.finding or result.error_code or "security_case_failed"
            findings.append(
                LabFinding(
                    finding_id=f"{run_id}:{index}",
                    case_id=result.case.case_id,
                    scenario_id=result.case.scenario_id,
                    severity=result.case.severity if result.status == "fail" else "high",
                    category=result.case.layer,
                    message=message,
                    evidence_root=(result.observation.evidence_root if result.observation else None),
                )
            )

        finished_at = datetime.now(timezone.utc).isoformat()
        base = {
            "tenant_id": tenant_id,
            "run_id": run_id,
            "schema": REPORT_SCHEMA,
            "started_at": started_at,
            "finished_at": finished_at,
            "seed": seed,
            "labels": list(labels),
            "total_cases": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "duration_ms": round(duration_ms, 3),
            "coverage_pct": coverage_pct,
            "findings": [item.to_dict() for item in findings],
            "case_results": [item.to_dict() for item in results],
        }
        report_hash = hashlib.sha256(cls._canonical_without_hash(base)).hexdigest()
        return cls(
            tenant_id=tenant_id,
            run_id=run_id,
            schema=REPORT_SCHEMA,
            started_at=started_at,
            finished_at=finished_at,
            seed=seed,
            labels=tuple(labels),
            total_cases=total,
            passed=passed,
            failed=failed,
            errors=errors,
            duration_ms=round(duration_ms, 3),
            coverage_pct=coverage_pct,
            findings=tuple(findings),
            case_results=tuple(results),
            report_hash=report_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "schema": self.schema,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "seed": self.seed,
            "labels": list(self.labels),
            "total_cases": self.total_cases,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
            "coverage_pct": self.coverage_pct,
            "findings": [item.to_dict() for item in self.findings],
            "case_results": [item.to_dict() for item in self.case_results],
            "report_hash": self.report_hash,
        }

    def verify_hash(self) -> bool:
        payload = self.to_dict()
        expected = hashlib.sha256(self._canonical_without_hash(payload)).hexdigest()
        return expected == self.report_hash
