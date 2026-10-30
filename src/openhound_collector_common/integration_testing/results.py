"""Result + Summary model and JSON serialization."""

from __future__ import annotations

import json
import logging
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"
logger = logging.getLogger(__name__)


@dataclass
class Result:
    case_id: str
    kind: str
    description: str
    outcome: str  # PASS | FAIL | SKIP
    detail: str = ""
    matched_count: int = 0


@dataclass
class Summary:
    results: list[Result] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.outcome == PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.outcome == FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.outcome == SKIP)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "results": [asdict(r) for r in self.results],
        }


def write_results_json(summary: Summary, path: Path) -> None:
    Path(path).write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")


def require_case_results(summary: Summary, expected_ids: Iterable[str]) -> None:
    """Make missing, repeated, skipped, or unexpected case results fail the run.

    Call before appending unrelated stage/invariant results. A successful process
    with no parsed case results must never be accepted as a completed test run.
    This is opt-in so existing suites can still contain deliberate placeholders.
    """
    expected = list(expected_ids)
    expected_counts = Counter(expected)
    actual_counts = Counter(result.case_id for result in summary.results)
    failures: list[Result] = []

    def fail(identifier: str, description: str) -> None:
        logger.error("Incomplete test accounting: %s", description)
        failures.append(
            Result(f"accounting:{identifier}", "case accounting", description, FAIL)
        )

    if not expected:
        fail("empty-selection", "No cases were selected")
    # Each selected case must have exactly one executed result.
    for identifier, count in expected_counts.items():
        if count != 1:
            fail(
                f"selection:{identifier}", f"Case selected more than once: {identifier}"
            )
        if actual_counts[identifier] == 0:
            fail(
                f"missing:{identifier}",
                f"Missing result for selected case: {identifier}",
            )
        elif actual_counts[identifier] != 1:
            fail(
                f"duplicate:{identifier}",
                f"Repeated result for selected case: {identifier}",
            )
        # One result is the ordinary successful accounting path.
    for result in summary.results:
        if result.case_id not in expected_counts:
            fail(
                f"unknown:{result.case_id}", f"Unexpected case result: {result.case_id}"
            )
        if result.outcome not in (PASS, FAIL):
            fail(
                f"not-executed:{result.case_id}",
                f"Case did not execute a pass/fail assertion: {result.case_id}",
            )
        # An executed failure remains a failure without another synthetic result.
    summary.results.extend(failures)
