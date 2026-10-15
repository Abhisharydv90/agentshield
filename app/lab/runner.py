"""Deterministic, side-effect-limited security test runner.

Phase 9 intentionally treats attacker inputs as data. A LabTarget is a pure
or near-pure callable supplied by the caller. The runner never invokes shell
commands, starts a process, contacts the network, or turns a test payload into
real-world authority.

The interface is versioned for later AURAGENT phases so Phase 10+ can consume
run results without rewriting this module.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping, Protocol

LAB_CASE_SCHEMA = "auragent.lab.case.v1"
LAB_RESULT_SCHEMA = "auragent.lab.result.v1"


class LabTarget(Protocol):
    def __call__(self, case: "LabCase") -> "LabObservation": ...


@dataclass(frozen=True)
class LabCase:
    """One security test input and its expected boundary outcome."""

    case_id: str
    scenario_id: str
    name: str
    layer: str
    payload: Any
    expected_decision: str = "deny"
    expected_tool_execution: bool = False
    severity: str = "high"
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def payload_hash(self) -> str:
        encoded = json.dumps(
            self.payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": LAB_CASE_SCHEMA,
            "case_id": self.case_id,
            "scenario_id": self.scenario_id,
            "name": self.name,
            "layer": self.layer,
            "payload_hash": self.payload_hash,
            "expected_decision": self.expected_decision,
            "expected_tool_execution": self.expected_tool_execution,
            "severity": self.severity,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class LabObservation:
    """What the protected system observed during a security test."""

    decision: str
    reason: str = ""
    authority_granted: bool = False
    tool_executed: bool = False
    evidence_root: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "authority_granted": self.authority_granted,
            "tool_executed": self.tool_executed,
            "evidence_root": self.evidence_root,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class LabCaseResult:
    case: LabCase
    observation: LabObservation | None
    status: str
    duration_ms: float
    error_code: str | None = None
    finding: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": LAB_RESULT_SCHEMA,
            "case": self.case.to_dict(),
            "observation": self.observation.to_dict() if self.observation else None,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 3),
            "error_code": self.error_code,
            "finding": self.finding,
        }


class LabRunner:
    """Executes bounded security cases against a supplied target."""

    def __init__(self, *, per_case_timeout_ms: int = 5_000) -> None:
        if per_case_timeout_ms < 1 or per_case_timeout_ms > 60_000:
            raise ValueError("per_case_timeout_ms_out_of_range")
        self.per_case_timeout_ms = per_case_timeout_ms

    @staticmethod
    def _validate_observation(observation: LabObservation) -> None:
        if observation.decision not in {"allow", "deny", "error"}:
            raise ValueError("invalid_lab_decision")

    @staticmethod
    def _evaluate(case: LabCase, observation: LabObservation) -> tuple[str, str | None]:
        decision_ok = observation.decision == case.expected_decision
        tool_ok = observation.tool_executed == case.expected_tool_execution

        if decision_ok and tool_ok:
            return "pass", None

        mismatches: list[str] = []
        if not decision_ok:
            mismatches.append("unexpected_decision")
        if not tool_ok:
            mismatches.append("unexpected_tool_execution")
        if case.expected_decision == "deny" and observation.authority_granted:
            mismatches.append("authority_granted_during_denial_case")

        return "fail", ";".join(mismatches)

    def run_case(self, case: LabCase, target: LabTarget) -> LabCaseResult:
        started = time.perf_counter()
        try:
            observation = target(case)
            if inspect.isawaitable(observation):
                import asyncio

                observation = asyncio.run(observation)
            duration_ms = (time.perf_counter() - started) * 1000.0
            if duration_ms > self.per_case_timeout_ms:
                return LabCaseResult(
                    case=case,
                    observation=observation,
                    status="error",
                    duration_ms=duration_ms,
                    error_code="target_timeout",
                    finding="target_timeout",
                )
            self._validate_observation(observation)
            status, finding = self._evaluate(case, observation)
            return LabCaseResult(
                case=case,
                observation=observation,
                status=status,
                duration_ms=duration_ms,
                finding=finding,
            )
        except TimeoutError:
            return LabCaseResult(
                case=case,
                observation=None,
                status="error",
                duration_ms=(time.perf_counter() - started) * 1000.0,
                error_code="target_timeout",
                finding="target_timeout",
            )
        except Exception:
            return LabCaseResult(
                case=case,
                observation=None,
                status="error",
                duration_ms=(time.perf_counter() - started) * 1000.0,
                error_code="target_exception",
                finding="target_exception",
            )

    def run_cases(self, cases: list[LabCase], target: LabTarget) -> list[LabCaseResult]:
        if len(cases) > 2_000:
            raise ValueError("lab_case_limit_exceeded")
        return [self.run_case(case, target) for case in cases]


def stable_case_id(scenario_id: str, payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"{scenario_id}:{digest}"
