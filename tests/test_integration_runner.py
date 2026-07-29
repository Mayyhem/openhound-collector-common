from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase, NodePattern, CountSpec
from openhound_collector_common.integration_testing.results import Result, PASS, FAIL, SKIP
from openhound_collector_common.integration_testing.runner import run_edge_case, run_node_case, run_suite

def _graph():
    return Graph(
        nodes=[Node("A", ["Group", "Base"], {}), Node("B", ["Computer", "Base"], {}),
               Node("S", ["SCCM_Site"], {"siteCode": "PS1"})],
        edges=[Edge("SCCM_CoerceAndRelayToSMB", "A", "B", {}),
               Edge("SCCM_CoerceAndRelayToSMB", "A", "B", {})])

def test_edge_default_at_least_one_passes():
    r = run_edge_case(EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d",
                               source=NodePattern(kinds=["Group"])), _graph())
    assert r.outcome == PASS and r.matched_count == 2

def test_edge_exact_count_fails():
    r = run_edge_case(EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d",
                               source=NodePattern(kinds=["Group"]), count=CountSpec(exact=1)), _graph())
    assert r.outcome == FAIL and "wrong count" in r.detail

def test_edge_no_constraints_skips():
    assert run_edge_case(EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d"), _graph()).outcome == SKIP

def test_edge_negative_passes_when_absent():
    r = run_edge_case(EdgeCase("e", "SCCM_FullAdministrator", "d",
                               source=NodePattern(kinds=["Group"]), negative=True), _graph())
    assert r.outcome == PASS

def test_node_count_at_least():
    r = run_node_case(NodeCase("n", "d", ["SCCM_Site"], count=CountSpec(at_least=1)), _graph())
    assert r.outcome == PASS and r.matched_count == 1

def test_run_suite_aggregates_and_runs_invariant(tmp_path):
    captured = []
    def inv(g): return Result("inv-1", "invariant", "always true", PASS)
    s = run_suite(_graph(),
                  edge_cases=[EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d", source=NodePattern(kinds=["Group"]))],
                  node_cases=[NodeCase("n", "d", ["SCCM_Site"])],
                  invariants=[inv], results_path=tmp_path / "r.json", log=captured.append)
    assert s.passed == 3 and s.failed == 0
    assert (tmp_path / "r.json").exists()
    assert any("Edge Test Summary" in line for line in captured)
