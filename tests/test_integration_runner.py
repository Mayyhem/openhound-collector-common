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


# --- con-acdd: distinguish "no such edge" from "edge rejected by property match" ---
#
# Both used to report FAIL "not found". They are opposite problems: one means the
# collector never produced the edge, the other means it produced it and an endpoint
# or edge property did not match. Conflating them cost real debugging time in the
# SCCM collector -- three separate tickets were opened to hunt for edges that were
# being emitted correctly the whole time. Their shared endpoint node was missing a
# samAccountName, so the matcher rejected otherwise-correct edges and every one of
# them reported "not found", pointing the investigation at collection instead of at
# the one property that was actually absent.

def _graph_with_named_endpoint(name="wrong-name"):
    return Graph(
        nodes=[Node("A", ["Group", "Base"], {}),
               Node("B", ["Computer", "Base"], {"samAccountName": name})],
        edges=[Edge("SCCM_CoerceAndRelayToSMB", "A", "B", {})])


def test_edge_absent_still_reports_not_found():
    """No candidate of that kind at all -- the collector produced nothing."""
    r = run_edge_case(
        EdgeCase("e", "SCCM_FullAdministrator", "d", source=NodePattern(kinds=["Group"])),
        _graph_with_named_endpoint())
    assert r.outcome == FAIL and r.detail == "not found"


def test_edge_rejected_by_property_reports_property_mismatch():
    """Candidates exist but every one was rejected -- say so, and say how many."""
    r = run_edge_case(
        EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d",
                 source=NodePattern(kinds=["Group"]),
                 target=NodePattern(kinds=["Computer"],
                                    properties={"samAccountName": "sqlsccmsvc"})),
        _graph_with_named_endpoint())
    assert r.outcome == FAIL
    assert "property mismatch" in r.detail, r.detail
    assert "1 candidate" in r.detail, r.detail


def test_node_rejected_by_property_reports_property_mismatch():
    """Same distinction for node cases."""
    r = run_node_case(
        NodeCase("n", "d", ["Computer"], properties={"samAccountName": "sqlsccmsvc"}),
        _graph_with_named_endpoint())
    assert r.outcome == FAIL
    assert "property mismatch" in r.detail, r.detail


def test_node_absent_still_reports_not_found():
    r = run_node_case(NodeCase("n", "d", ["SCCM_AdminUser"]), _graph_with_named_endpoint())
    assert r.outcome == FAIL and r.detail == "not found"
