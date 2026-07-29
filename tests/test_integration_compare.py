from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.compare import compare_graphs

def test_compare_nodes_edges_and_rollup():
    a = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "PS1", "versionCVEs": ["CVE-1"], "src": ["A", "B"]}),
               Node("N2", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "X", {"traversable": True})])
    b = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "CAS", "src": ["B", "A"]}),
               Node("N3", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "Y", {"traversable": True})])
    rep = compare_graphs(a, b)
    assert rep.nodes_only_in_a == ["N2"] and rep.nodes_only_in_b == ["N3"]
    assert rep.edges_only_in_a == ["N1|SCCM_HasClient|X"]
    assert rep.edges_only_in_b == ["N1|SCCM_HasClient|Y"]
    nd = next(d for d in rep.node_prop_diffs if d.key == "N1")
    assert nd.changed["siteCode"] == ["PS1", "CAS"]          # value differs
    assert "versionCVEs" in nd.only_in_a                      # present in A only
    assert "src" not in nd.changed and "src" not in nd.only_in_a  # list order-insensitive == equal
    # by-kind rollup: versionCVEs appears on SCCM_Site in A but not B
    assert "versionCVEs" in rep.node_kind_rollup["SCCM_Site"]["only_a"]
