"""Result + Summary model and JSON serialization."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclass
class Result:
    case_id: str
    kind: str
    description: str
    outcome: str          # PASS | FAIL | SKIP
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
        return {"passed": self.passed, "failed": self.failed, "skipped": self.skipped,
                "results": [asdict(r) for r in self.results]}


def write_results_json(summary: Summary, path: Path) -> None:
    Path(path).write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
