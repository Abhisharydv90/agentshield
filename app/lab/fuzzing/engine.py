"""Bounded deterministic fuzz case generator and executor."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from app.lab.fuzzing.mutators import MUTATORS
from app.lab.runner import LabCase, LabCaseResult, LabRunner, LabTarget, stable_case_id


@dataclass(frozen=True)
class FuzzResult:
    seed: int
    generated: int
    executed: int
    failures: int
    errors: int


class FuzzEngine:
    def __init__(self, *, seed: int = 0, max_cases: int = 100) -> None:
        if max_cases < 1 or max_cases > 2_000:
            raise ValueError("fuzz_case_limit_out_of_range")
        self.seed = int(seed)
        self.max_cases = int(max_cases)

    def build_cases(self, seeds: Iterable[Any]) -> list[LabCase]:
        base = list(seeds)[:64]
        if not base:
            base = ["baseline"]
        rng = random.Random(self.seed)
        cases: list[LabCase] = []
        for index in range(self.max_cases):
            source = base[index % len(base)]
            mutator = MUTATORS[index % len(MUTATORS)]
            payload = mutator(source, rng)
            cases.append(
                LabCase(
                    case_id=stable_case_id("fuzz", payload),
                    scenario_id="fuzz",
                    name=f"fuzz-{index:04d}-{mutator.__name__}",
                    layer="input",
                    payload=payload,
                    expected_decision="deny" if mutator.__name__ == "mutate_injection" else "allow",
                    expected_tool_execution=False,
                    severity="medium",
                    tags=("fuzz", mutator.__name__),
                )
            )
        return cases

    def run(self, *, seeds: Iterable[Any], runner: LabRunner, target: LabTarget) -> tuple[list[LabCaseResult], FuzzResult]:
        cases = self.build_cases(seeds)
        results = runner.run_cases(cases, target)
        return results, FuzzResult(
            seed=self.seed,
            generated=len(cases),
            executed=len(results),
            failures=sum(result.status == "fail" for result in results),
            errors=sum(result.status == "error" for result in results),
        )
