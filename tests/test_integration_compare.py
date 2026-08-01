from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.compare import compare_graphs


def test_compare_nodes_edges_and_rollup():
    # baseline = what came first; candidate = what is being compared against it.
    baseline = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "PS1", "versionCVEs": ["CVE-1"], "src": ["A", "B"]}),
               Node("N2", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "X", {"traversable": True})])
    candidate = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "CAS", "src": ["B", "A"]}),
               Node("N3", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "Y", {"traversable": True})])
    rep = compare_graphs(baseline, candidate)

    assert rep.nodes_only_in_baseline == ["N2"]
    assert rep.nodes_only_in_candidate == ["N3"]
    assert rep.edges_only_in_baseline == ["N1|SCCM_HasClient|X"]
    assert rep.edges_only_in_candidate == ["N1|SCCM_HasClient|Y"]

    nd = next(d for d in rep.node_prop_diffs if d.key == "N1")
    assert nd.changed["siteCode"] == {"baseline": "PS1", "candidate": "CAS"}
    assert "versionCVEs" in nd.only_in_baseline          # baseline had it, candidate does not
    # list equality is order-insensitive, so a reordered list is not a difference at all
    assert "src" not in nd.changed and "src" not in nd.only_in_baseline

    assert "versionCVEs" in rep.node_kind_rollup["SCCM_Site"]["only_in_baseline"]
    assert rep.node_kind_rollup["SCCM_Site"]["only_in_candidate"] == []


def test_to_dict_uses_renamed_keys():
    baseline = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    candidate = Graph(nodes=[], edges=[])
    d = compare_graphs(baseline, candidate).to_dict()
    assert d["nodes_only_in_baseline"] == ["N1"]
    assert d["nodes_only_in_candidate"] == []
    # the old A/B key names must be gone entirely, so stale readers fail loudly
    assert not [k for k in d if k.endswith("_a") or k.endswith("_b")]
