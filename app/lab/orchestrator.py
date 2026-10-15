"""Phase 9 Security Lab orchestration layer.

AttackForge = deterministic attack/scenario execution.
SecurityBench = regression + benchmark aggregation.

The orchestrator is intentionally transport-neutral. API, scheduled jobs, CI,
and the future Control Plane can all call the same interface.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from app.lab.corpus.store import CorpusEntry, CorpusStore
from app.lab.fuzzing.engine import FuzzEngine, FuzzResult
from app.lab.reports import LabFinding, LabRunReport
from app.lab.runner import LabCase, LabCaseResult, LabRunner, LabTarget
from app.lab.scenarios.red_team import ScenarioCatalog
from app.lab.scenarios.simulation import default_security_simulator


@dataclass(frozen=True)
class LabRunRequest:
    scenario_ids: tuple[str, ...] = ()
    seed: int = 0
    fuzz: bool = False
    fuzz_cases: int = 100
    labels: tuple[str, ...] = ()


class LabOrchestrator:
    """Owns scenario catalog, corpus, run history, and deterministic reports."""

    def __init__(self, *, runner: LabRunner | None = None) -> None:
        self.runner = runner or LabRunner()
        self.catalog = ScenarioCatalog()
        self.corpus_by_tenant: dict[str, CorpusStore] = {}
        self.reports_by_tenant: dict[str, dict[str, LabRunReport]] = {}
        self.last_run_by_tenant: dict[str, str] = {}

    def _corpus(self, tenant_id: str) -> CorpusStore:
        return self.corpus_by_tenant.setdefault(tenant_id, CorpusStore())

    def _reports(self, tenant_id: str) -> dict[str, LabRunReport]:
        return self.reports_by_tenant.setdefault(tenant_id, {})

    def list_scenarios(self) -> list[dict[str, Any]]:
        return [scenario.to_dict() for scenario in self.catalog.scenarios]

    def add_corpus_case(
        self,
        *,
        tenant_id: str,
        payload: Any,
        source: str = "manual",
        labels: Iterable[str] = (),
        metadata: dict[str, Any] | None = None,
    ) -> CorpusEntry:
        return self._corpus(tenant_id).add(
            payload=payload,
            source=source,
            labels=tuple(labels),
            metadata=metadata or {},
        )

    def list_corpus(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        return [item.to_dict(redact_payload=False) for item in self._corpus(tenant_id).list(limit=limit)]

    def get_report(self, tenant_id: str, run_id: str) -> LabRunReport | None:
        return self._reports(tenant_id).get(run_id)

    def list_reports(self, tenant_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = list(self._reports(tenant_id).values())[-limit:]
        rows.reverse()
        return [report.to_dict() for report in rows]

    def _cases(self, scenario_ids: tuple[str, ...]) -> list[LabCase]:
        selected = self.catalog.select(scenario_ids)
        cases: list[LabCase] = []
        for scenario in selected:
            cases.extend(scenario.build_cases())
        return cases

    def run(
        self,
        *,
        tenant_id: str,
        request: LabRunRequest,
        target: LabTarget | None = None,
    ) -> LabRunReport:
        target = target or default_security_simulator
        run_id = str(uuid.uuid4())
        cases = self._cases(request.scenario_ids)
        if request.fuzz:
            fuzz_inputs = [item.payload for item in self._corpus(tenant_id).list(limit=100)]
            engine = FuzzEngine(seed=request.seed, max_cases=request.fuzz_cases)
            cases.extend(engine.build_cases(fuzz_inputs or ["safe baseline"]))

        if len(cases) > 2_000:
            raise ValueError("lab_case_limit_exceeded")

        results = self.runner.run_cases(cases, target)
        report = LabRunReport.build(
            tenant_id=tenant_id,
            run_id=run_id,
            seed=request.seed,
            results=results,
            labels=request.labels,
        )
        self._reports(tenant_id)[run_id] = report
        self.last_run_by_tenant[tenant_id] = run_id
        return report

    def benchmark(self, *, tenant_id: str, target: LabTarget | None = None) -> LabRunReport:
        return self.run(
            tenant_id=tenant_id,
            request=LabRunRequest(
                scenario_ids=tuple(item.scenario_id for item in self.catalog.scenarios),
                seed=0,
                fuzz=False,
                labels=("securitybench", "deterministic"),
            ),
            target=target,
        )
