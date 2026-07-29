import json
from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase
from openhound_collector_common.integration_testing.coverage import coverage

def test_coverage(tmp_path):
    schema = {"node_kinds": [{"name": "SCCM_Site"}, {"name": "SCCM_Collection"}],
              "relationship_kinds": [{"name": "SCCM_HasClient"}, {"name": "SCCM_HasMember"}]}
    p = tmp_path / "schema.json"
    p.write_text(json.dumps(schema), encoding="utf-8")
    cov = coverage(p, edge_cases=[EdgeCase("e", "SCCM_HasClient", "d")],
                   node_cases=[NodeCase("n", "d", ["SCCM_Site"])])
    assert cov["untested_edge_kinds"] == ["SCCM_HasMember"]
    assert cov["untested_node_kinds"] == ["SCCM_Collection"]
