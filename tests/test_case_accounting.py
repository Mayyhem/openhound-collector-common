"""A zero exit code cannot compensate for absent or incomplete case results."""

import pytest

from openhound_collector_common.integration_testing.results import (
    Result,
    Summary,
    require_case_results,
)


@pytest.mark.parametrize(
    "identifiers,results",
    [
        ([], []),
        (["required"], []),
        (["required"], [Result("required", "edge", "d", "SKIP")]),
        (["required"], [Result("other", "edge", "d", "PASS")]),
        (["required"], [Result("required", "edge", "d", "PASS")] * 2),
        (["required", "required"], [Result("required", "edge", "d", "PASS")]),
    ],
)
def test_missing_skipped_unknown_and_duplicate_results_fail(identifiers, results):
    summary = Summary(results=list(results))
    require_case_results(summary, identifiers)
    assert summary.failed >= 1
    assert any(result.case_id.startswith("accounting:") for result in summary.results)


def test_complete_execution_preserves_real_pass_and_fail_results():
    summary = Summary(
        [Result("passed", "edge", "d", "PASS"), Result("failed", "edge", "d", "FAIL")]
    )
    require_case_results(summary, ["passed", "failed"])
    assert summary.passed == 1
    assert summary.failed == 1
    assert len(summary.results) == 2
