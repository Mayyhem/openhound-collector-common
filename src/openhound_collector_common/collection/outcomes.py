"""Saved outcomes distinguish an empty successful read from a failed operation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


@dataclass(frozen=True)
class OperationResult:
    """A non-secret account of one attempted read; callers select safe labels.

    Never store the query, credentials, or an unfiltered exception here. A fixed
    failure category describes what failed; detailed redacted errors belong in
    the run's logs. A successful zero-row read remains a completed operation.
    """

    operation: str
    state: Literal["completed", "failed", "skipped"]
    row_count: int | None
    elapsed_ms: int
    failure_category: str | None = None

    def __post_init__(self) -> None:
        if not self.operation.strip() or self.state not in (
            "completed",
            "failed",
            "skipped",
        ):
            raise ValueError(
                "An operation needs a name and completed/failed/skipped state"
            )
        if self.elapsed_ms < 0:
            raise ValueError("An operation duration cannot be negative")
        if self.state == "completed":
            if (
                self.row_count is None
                or self.row_count < 0
                or self.failure_category is not None
            ):
                raise ValueError(
                    "A completed read needs a nonnegative row count and no failure category"
                )
        elif self.row_count is not None:
            raise ValueError("A failed or skipped read must not claim a row count")

    def as_row(self) -> dict[str, str | int | None]:
        """Return a flat saved row; TargetRowWriter supplies run/target ownership."""
        return asdict(self)


@dataclass(frozen=True)
class TargetResult:
    """One target's saved completion state, independent of a collector's exit policy."""

    target_id: str
    state: Literal["completed", "partial", "failed", "skipped", "stopped"]
    row_count: int
    operations_completed: int = 0
    operations_failed: int = 0
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self.target_id or self.state not in (
            "completed",
            "partial",
            "failed",
            "skipped",
            "stopped",
        ):
            raise ValueError(
                "A target result needs an identity and a known completion state"
            )
        if min(self.row_count, self.operations_completed, self.operations_failed) < 0:
            raise ValueError("Target result counts cannot be negative")
        if self.state == "completed" and self.operations_failed:
            raise ValueError(
                "A target with failed operations cannot be called completed"
            )

    def as_row(self) -> dict[str, str | int | None]:
        """Return a non-secret row with target_id already supplied by the row writer."""
        return {
            name: value for name, value in asdict(self).items() if name != "target_id"
        }


@dataclass(frozen=True)
class RunResult:
    """A run's target outcomes; the consuming collector chooses its exit policy."""

    run_id: str
    targets: tuple[TargetResult, ...]
    stop_reason: str | None = None

    @property
    def has_incomplete_work(self) -> bool:
        """Intentional skips do not count as missing requested work."""
        return self.stop_reason is not None or any(
            target.state in ("partial", "failed", "stopped") for target in self.targets
        )

    @property
    def has_saved_rows(self) -> bool:
        """Whether targets saved data rows, excluding status and run-description rows."""
        return any(target.row_count > 0 for target in self.targets)

    def counts(self) -> dict[str, int]:
        """Count every known state explicitly, including states with zero targets."""
        return {
            state: sum(target.state == state for target in self.targets)
            for state in ("completed", "partial", "failed", "skipped", "stopped")
        }
