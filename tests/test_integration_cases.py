from openhound_collector_common.integration_testing.cases import CountSpec, EdgeCase, NodeCase

def test_countspec_semantics():
    assert CountSpec(exact=3).satisfied_by(3) and not CountSpec(exact=3).satisfied_by(2)
    assert CountSpec(at_least=2).satisfied_by(5) and not CountSpec(at_least=2).satisfied_by(1)
    assert CountSpec(at_most=2).satisfied_by(2) and not CountSpec(at_most=2).satisfied_by(3)
    assert CountSpec(at_least=1, at_most=3).satisfied_by(2)
    assert CountSpec().satisfied_by(999)  # no bounds => any

def test_case_defaults():
    e = EdgeCase(id="e1", kind="SCCM_HasClient", description="d")
    assert e.source is None and e.negative is False and e.count is None
    n = NodeCase(id="n1", description="d", kinds=["SCCM_Site"])
    assert n.properties is None and n.count is None
