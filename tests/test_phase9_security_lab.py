from __future__ import annotations

from app.lab.corpus.store import CorpusStore
from app.lab.fuzzing.engine import FuzzEngine
from app.lab.orchestrator import LabOrchestrator, LabRunRequest
from app.lab.reports import LabRunReport
from app.lab.runner import LabObservation, LabRunner
from app.lab.scenarios.red_team import ScenarioCatalog
from app.lab.scenarios.simulation import default_security_simulator


def test_scenario_catalog_is_stable_and_complete() -> None:
    catalog = ScenarioCatalog()
    ids = [item.scenario_id for item in catalog.scenarios]
    assert ids == [
        "prompt-injection",
        "unicode-obfuscation",
        "external-content-instruction",
        "tool-protocol-confusion",
        "capability-escalation",
        "memory-poisoning",
        "authority-laundering",
        "approval-bypass",
        "benign-controls",
    ]


def test_default_security_suite_passes_against_reference_target() -> None:
    orchestrator = LabOrchestrator()
    report = orchestrator.run(
        tenant_id="tenant-a",
        request=LabRunRequest(seed=0),
        target=default_security_simulator,
    )
    assert report.failed == 0
    assert report.errors == 0
    assert report.passed == report.total_cases
    assert report.verify_hash()


def test_fuzzing_is_deterministic() -> None:
    engine_a = FuzzEngine(seed=42, max_cases=16)
    engine_b = FuzzEngine(seed=42, max_cases=16)
    a = [case.payload_hash for case in engine_a.build_cases(["baseline"])]
    b = [case.payload_hash for case in engine_b.build_cases(["baseline"])]
    assert a == b


def test_corpus_deduplicates_by_content_hash() -> None:
    corpus = CorpusStore()
    first = corpus.add(payload={"x": 1}, source="unit")
    second = corpus.add(payload={"x": 1}, source="unit")
    assert first.entry_id == second.entry_id
    assert corpus.count() == 1


def test_runner_flags_policy_regression() -> None:
    case = ScenarioCatalog().select(("capability-escalation",))[0].build_cases()[0]
    runner = LabRunner()

    def bad_target(_case):
        return LabObservation(
            decision="allow",
            reason="unsafe",
            authority_granted=True,
            tool_executed=True,
        )

    result = runner.run_case(case, bad_target)
    assert result.status == "fail"
    assert "unexpected_decision" in (result.finding or "")


def test_report_hash_detects_tampering() -> None:
    orchestrator = LabOrchestrator()
    report = orchestrator.run(
        tenant_id="tenant-a",
        request=LabRunRequest(scenario_ids=("prompt-injection",)),
        target=default_security_simulator,
    )
    assert report.verify_hash()
    tampered = report.to_dict()
    tampered["passed"] = tampered["passed"] + 1
    assert LabRunReport._canonical_without_hash(tampered) != LabRunReport._canonical_without_hash(report.to_dict())
