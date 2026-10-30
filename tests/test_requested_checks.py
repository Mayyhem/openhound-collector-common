"""A broken requested check/report must not hide another requested result."""

import json

import pytest

from openhound_collector_common.integration_testing.results import Result, Summary
from openhound_collector_common.integration_testing.reports import write_summary_reports
from openhound_collector_common.integration_testing.validation import (
    RequestedCheck,
    run_requested_checks,
)


@pytest.mark.parametrize("collection_code", [0, 1, 3])
@pytest.mark.parametrize(
    "first_failure",
    [None, "assertion", "exception", "missing", "invalid-json", "invalid-status"],
)
def test_every_check_runs_and_failure_takes_precedence(
    tmp_path, collection_code, first_failure
):
    calls = []
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    def first_check():
        calls.append("first")
        if first_failure == "exception":
            raise RuntimeError("Sensitive value must not enter the report")
        if first_failure == "invalid-status":
            return None
        if first_failure != "missing":
            first.write_text("{" if first_failure == "invalid-json" else "{}")
        return int(first_failure == "assertion")

    def second_check():
        calls.append("second")
        second.write_text("{}")
        return 0

    result = run_requested_checks(
        [
            RequestedCheck("first", first_check, first),
            RequestedCheck("second", second_check, second),
        ],
        collection_exit_code=collection_code,
    )
    assert calls == ["first", "second"]
    assert result.exit_code == (1 if first_failure else collection_code)
    assert [check.exit_code for check in result.checks] == [int(bool(first_failure)), 0]
    assert "Sensitive value" not in first.read_text()
    assert second.exists()


def test_old_report_cannot_stand_in_for_an_unexecuted_check(tmp_path):
    report = tmp_path / "old.json"
    report.write_text('{"passed": 50}')
    calls = []
    result = run_requested_checks(
        [RequestedCheck("old", lambda: calls.append(True) or 0, report)]
    )
    assert result.exit_code == 1 and calls == []
    assert json.loads(report.read_text()) == {"passed": 50}


def test_failure_to_write_one_report_does_not_prevent_the_next(tmp_path):
    missing_parent = tmp_path / "missing" / "report.json"
    good = tmp_path / "good.json"

    def write_good():
        good.write_text("{}")
        return 0

    result = run_requested_checks(
        [
            RequestedCheck("unwritable", lambda: 0, missing_parent),
            RequestedCheck("good", write_good, good),
        ]
    )
    assert result.exit_code == 1 and good.exists()


def test_html_is_self_contained_escaped_and_keeps_individual_results(tmp_path):
    summary = Summary(
        [
            Result(
                "case-1",
                "Edge",
                "<script>alert(1)</script>",
                "FAIL",
                "wrong <value>",
                2,
            )
        ]
    )
    report = tmp_path / "report.json"
    html = write_summary_reports(summary, report, context={"profile": "minimum<&>"})
    assert json.loads(report.read_text())["failed"] == 1
    document = html.read_text(encoding="utf-8")
    assert "<script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "minimum&lt;&amp;&gt;" in document
    assert "case-1" in document and "wrong &lt;value&gt;" in document


def test_html_write_failure_cannot_be_reported_as_success(tmp_path):
    report = tmp_path / "results.json"
    report.with_suffix(".html").mkdir()
    with pytest.raises(OSError):
        write_summary_reports(Summary(), report)
