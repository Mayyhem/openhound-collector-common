"""Keep failed reads distinct from successful empty reads in saved outcomes."""

import pytest

from openhound_collector_common.collection import OperationResult, RunResult, TargetResult


def test_empty_success_and_failed_read_have_different_saved_shapes():
    completed = OperationResult("principals", "completed", 0, 5)
    failed = OperationResult("principals", "failed", None, 5, "Read rejected")
    assert completed.as_row()["row_count"] == 0
    assert failed.as_row()["row_count"] is None
    assert failed.as_row()["state"] == "failed"


@pytest.mark.parametrize("state,count,category", [("completed", None, None), ("completed", -1, None), ("completed", 0, "Failure"), ("failed", 0, "Failure"), ("skipped", 0, None)])
def test_outcome_cannot_claim_a_row_count_for_an_uncompleted_read(state, count, category):
    with pytest.raises(ValueError):
        OperationResult("principals", state, count, 5, category)


def test_run_summary_uses_recorded_states_rather_than_warnings():
    empty = RunResult("run", ())
    assert not empty.has_incomplete_work
    assert empty.counts() == {"completed": 0, "partial": 0, "failed": 0, "skipped": 0, "stopped": 0}
    skipped = RunResult("run", (TargetResult("excluded", "skipped", 0),))
    assert not skipped.has_incomplete_work
    partial = RunResult("run", (TargetResult("good", "completed", 1), TargetResult("bad", "failed", 0)))
    assert partial.has_incomplete_work and partial.has_saved_rows
    assert partial.counts()["completed"] == partial.counts()["failed"] == 1


def test_completed_target_cannot_conceal_failed_operations():
    with pytest.raises(ValueError, match="failed operations"):
        TargetResult("target", "completed", 1, operations_failed=1)
