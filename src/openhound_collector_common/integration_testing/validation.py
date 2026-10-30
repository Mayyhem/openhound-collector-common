"""Attempt every requested saved-graph check before combining command status."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from openhound_collector_common.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class RequestedCheck:
    """One caller-owned check and its fresh, uniquely named JSON report."""

    name: str
    run: Callable[[], int]
    report_path: Path


@dataclass(frozen=True)
class CheckOutcome:
    """A check fails on an assertion, exception, or absent/invalid report."""

    name: str
    exit_code: int
    report_path: Path


@dataclass(frozen=True)
class ValidationOutcome:
    """Individual checks and the final collection-aware command status."""

    checks: tuple[CheckOutcome, ...]
    exit_code: int


def run_requested_checks(
    checks: Sequence[RequestedCheck], *, collection_exit_code: int = 0
) -> ValidationOutcome:
    """Run independent checks even after a failure, preserving incomplete status.

    Call only once a graph is available. Callers choose profiles, comparisons,
    report names and assertions. They must supply fresh report paths: an older
    report must not stand in for a check that failed to write this run's result.
    Exceptions are logged through the caller's normal secret-filtered logging;
    generated failure reports never contain exception messages or credentials.
    """
    if collection_exit_code not in (0, 1, 3):
        logger.error("Invalid collection status for requested graph checks")
        raise ValueError("Expected collection exit code 0, 1 or 3")
    outcomes = []
    for check in checks:
        try:
            if check.report_path.exists():
                logger.error(
                    "Requested check report already exists: %s", check.report_path
                )
                raise FileExistsError("A fresh check report path is required")
            logger.info("Running requested check: %s", check.name)
            code = check.run()
            if type(code) is not int or code not in (0, 1):
                logger.error(
                    "Requested check %s returned an invalid status", check.name
                )
                raise ValueError("A check must return integer status 0 or 1")
            # A callback returning success without writing its report is not
            # evidence of an executed check. Parsing also rejects broken JSON.
            document = json.loads(check.report_path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                logger.error("Requested check %s wrote an invalid report", check.name)
                raise ValueError("A check report must be a JSON object")
            logger.info("Requested check %s finished with status %d", check.name, code)
        except Exception as error:
            logger.exception(
                "Requested check %s did not finish successfully", check.name
            )
            code = 1
            if not check.report_path.exists():
                try:
                    check.report_path.write_text(
                        json.dumps(
                            {
                                "check": check.name,
                                "status": "failed",
                                "exception_type": type(error).__name__,
                                "detail": "The check did not complete; see the run logs.",
                            },
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                except OSError:
                    logger.exception(
                        "Could not write failure report for %s", check.name
                    )
            # Preserve an existing or partial report for diagnosis; this
            # CheckOutcome still fails and the next requested check still runs.
        outcomes.append(CheckOutcome(check.name, code, check.report_path))
    code = 1 if any(outcome.exit_code for outcome in outcomes) else collection_exit_code
    return ValidationOutcome(tuple(outcomes), code)
