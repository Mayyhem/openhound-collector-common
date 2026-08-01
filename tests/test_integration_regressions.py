from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.compare import compare_graphs


def _cats(baseline, candidate):
    return {r.category for r in compare_graphs(baseline, candidate).regressions()}


def test_missing_node_is_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {})], edges=[])
    c = Graph(nodes=[], edges=[])
    assert "node-missing" in _cats(b, c)
    assert compare_graphs(b, c).has_regressions is True


def test_missing_edge_is_a_regression():
    b = Graph(nodes=[], edges=[Edge("K", "S", "E", {})])
    c = Graph(nodes=[], edges=[])
    assert "edge-missing" in _cats(b, c)


def test_lost_property_is_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {"p": 1, "q": 2})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    cats = _cats(b, c)
    assert "property-missing" in cats
    # the same loss also shows at kind granularity; both are reported
    assert "kind-property-missing" in cats


def test_property_emptied_is_a_regression():
    for empty in (None, "", [], {}):
        b = Graph(nodes=[Node("N1", ["K"], {"userName": "MAYYHEM\\bob"})], edges=[])
        c = Graph(nodes=[Node("N1", ["K"], {"userName": empty})], edges=[])
        assert "property-emptied" in _cats(b, c), f"{empty!r} should count as emptied"


def test_list_shrinking_is_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {"collectionSource": ["LDAP", "HTTP"]})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"collectionSource": ["LDAP"]})], edges=[])
    regs = compare_graphs(b, c).regressions()
    assert [r.category for r in regs].count("property-shrank") == 1
    assert "HTTP" in regs[0].detail


def test_edge_property_loss_is_a_regression():
    b = Graph(nodes=[], edges=[Edge("K", "S", "E", {"traversable": True, "why": "x"})])
    c = Graph(nodes=[], edges=[Edge("K", "S", "E", {"traversable": True})])
    assert "property-missing" in _cats(b, c)


# --- explicit non-regressions ------------------------------------------------

def test_additions_are_not_regressions():
    b = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"p": 1, "new": 2}), Node("N2", ["K"], {})],
              edges=[Edge("K", "S", "E", {})])
    assert compare_graphs(b, c).regressions() == []
    assert compare_graphs(b, c).has_regressions is False


def test_ordinary_value_change_is_not_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {"siteCode": "PS1"})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"siteCode": "CAS"})], edges=[])
    assert compare_graphs(b, c).regressions() == []


def test_list_growth_and_reorder_are_not_regressions():
    b = Graph(nodes=[Node("N1", ["K"], {"src": ["A", "B"]})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"src": ["B", "A", "C"]})], edges=[])
    assert compare_graphs(b, c).regressions() == []


def test_falsy_but_present_values_are_not_emptied():
    # 0 and False are real collected values, not absence.
    b = Graph(nodes=[Node("N1", ["K"], {"count": 5, "flag": True})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"count": 0, "flag": False})], edges=[])
    assert compare_graphs(b, c).regressions() == []


# --- rendering ---------------------------------------------------------------

def _render(baseline, candidate):
    lines = []
    compare_graphs(baseline, candidate).render(log=lines.append)
    return "\n".join(lines)


def test_render_reports_regressions_and_additions_separately():
    b = Graph(nodes=[Node("GONE", ["K"], {}), Node("N1", ["K"], {"lost": 1})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"gained": 2}), Node("NEW", ["K"], {})], edges=[])
    out = _render(b, c)
    assert "REGRESSIONS" in out and "ADDED" in out
    assert "GONE" in out and "NEW" in out
    assert out.index("REGRESSIONS") < out.index("ADDED")     # failures first
    assert "RESULT:" in out.splitlines()[-1]


def test_render_clean_run_says_so():
    g = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    out = _render(g, g)
    assert "RESULT: 0 regressions" in out
    assert "0 additions" in out


def test_kind_level_finding_prints_the_kind_once():
    """key and kind both hold the kind name; the rendered line must not repeat it."""
    b = Graph(nodes=[Node("N1", ["SCCM_Site"], {"versionCVEs": ["CVE-1"]})], edges=[])
    c = Graph(nodes=[Node("N1", ["SCCM_Site"], {})], edges=[])
    line = next(str(r) for r in compare_graphs(b, c).regressions()
                if r.category == "kind-property-missing")
    assert "SCCM_Site SCCM_Site" not in line
    assert line.count("SCCM_Site") == 1
    # the structured fields keep the kind, so callers can still filter on it
    reg = next(r for r in compare_graphs(b, c).regressions()
               if r.category == "kind-property-missing")
    assert reg.kind == "SCCM_Site" and reg.key == "SCCM_Site"
