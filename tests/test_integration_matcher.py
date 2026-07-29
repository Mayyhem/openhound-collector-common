from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.cases import NodePattern, EdgeCase
from openhound_collector_common.integration_testing.matcher import property_match, node_matches, edge_matches

def test_property_match_branches():
    assert property_match(None, None)
    assert not property_match(None, "x") and not property_match("x", None)
    assert property_match("MAYYHEM\\PS1$@x:1433", "*:1433")     # wildcard
    assert property_match("PS1", "ps1")                          # case-insensitive exact
    assert property_match(["a", "b", "c"], ["b"])               # list subset (expected in actual)
    assert not property_match(["a"], ["z"])
    assert property_match("True", True) and property_match("0", False)  # bool coercion

def test_node_matches_kinds_and_props():
    n = Node(id="MAYYHEM.COM-S-1-5-11", kinds=["Group", "Base"], properties={})
    assert node_matches(n, NodePattern(kinds=["Group"], properties={"id": "*-S-1-5-11"}))
    assert not node_matches(n, NodePattern(kinds=["User"]))

def test_edge_matches_full():
    g = Graph(
        nodes=[Node("A", ["Group", "Base"], {}), Node("B", ["MSSQL_Login"], {})],
        edges=[Edge("MSSQL_CoerceAndRelayToMSSQL", "A", "B", {"coercionVictimAndRelayTargetPairs": ["Coerce x, relay to y:1433"]})],
    )
    case = EdgeCase(id="c", kind="MSSQL_CoerceAndRelayToMSSQL", description="d",
                    source=NodePattern(kinds=["Group"], properties={"id": "A"}),
                    target=NodePattern(kinds=["MSSQL_Login"]),
                    properties={"coercionVictimAndRelayTargetPairs": ["Coerce x, relay to y:1433"]})
    assert edge_matches(g.edges[0], g, case)
    bad = EdgeCase(id="c2", kind="MSSQL_CoerceAndRelayToMSSQL", description="d",
                   target=NodePattern(kinds=["User"]))
    assert not edge_matches(g.edges[0], g, bad)
