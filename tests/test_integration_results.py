import json
from openhound_collector_common.integration_testing.results import (
    Result, Summary, write_results_json, PASS, FAIL, SKIP)

def test_summary_counts_and_dict():
    s = Summary(results=[
        Result("a", "K", "d", PASS, matched_count=2),
        Result("b", "K", "d", FAIL, "not found"),
        Result("c", "K", "d", SKIP)])
    assert (s.passed, s.failed, s.skipped) == (1, 1, 1)
    d = s.to_dict()
    assert d["passed"] == 1 and len(d["results"]) == 3 and d["results"][0]["matched_count"] == 2

def test_write_results_json(tmp_path):
    p = tmp_path / "r.json"
    write_results_json(Summary(results=[Result("a", "K", "d", PASS)]), p)
    assert json.loads(p.read_text())["results"][0]["case_id"] == "a"
