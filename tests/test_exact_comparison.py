"""Prove exact comparisons find losses hidden by ordinary regression checking."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from openhound_collector_common.integration_testing import cli
from openhound_collector_common.integration_testing.compare import compare_graphs
from openhound_collector_common.integration_testing.exact import PropertyAllowance
from openhound_collector_common.integration_testing.graph import Edge, Graph, Node


def node(**properties):
    return Node("server:51433", ["MSSQL_Server", "MSSQL"], properties)


@pytest.mark.parametrize("before,after", [(True, 1), (1, 1.0), ("owner-A", "owner-B"), (["A", "B"], ["B", "A"]), (None, ""), (False, True)])
def test_exact_mode_detects_type_value_and_list_order_changes(before, after):
    report = compare_graphs(Graph([node(value=before)], []), Graph([node(value=after)], []), exact=True)
    assert report.is_exact_match is False
    assert report.to_dict()["exact_record_differences"]


def test_added_record_and_changed_kind_fail_exact_comparison():
    baseline = Graph([node(port=51433)], [])
    for candidate in (Graph([node(port=51433), Node("extra", ["Computer"], {})], []), Graph([Node("server:51433", ["MSSQL_Database"], {"port": 51433})], [])):
        assert not compare_graphs(baseline, candidate, exact=True).is_exact_match


def test_kinds_are_unordered_labels_but_property_lists_keep_their_order():
    original = node(port=51433)
    reversed_kinds = replace(original, kinds=list(reversed(original.kinds)))
    assert compare_graphs(Graph([original], []), Graph([reversed_kinds], []), exact=True).is_exact_match


def test_linked_login_mappings_and_duplicate_counts_are_never_collapsed():
    first = Edge("MSSQL_LinkedTo", "local", "remote", {"localLogin": "first", "remoteLogin": "remote-first"})
    second = replace(first, properties={"localLogin": "second", "remoteLogin": "remote-second"})
    # The previous single-edge dictionary kept only the last record on each
    # side, making this particular loss invisible to the ordinary comparator.
    baseline = Graph([], [first, second])
    candidate = Graph([], [second])
    assert compare_graphs(baseline, candidate).has_regressions
    assert not compare_graphs(baseline, candidate, exact=True).is_exact_match
    assert compare_graphs(baseline, Graph([], [second, first]), exact=True).is_exact_match
    assert not compare_graphs(Graph([], [first, first]), Graph([], [first]), exact=True).is_exact_match


def test_endpoint_matching_rule_and_source_labels_are_compared():
    edge = Edge("MemberOf", "member", "group", {}, source_kind="MSSQL_Base")
    baseline = Graph([], [edge])
    assert not compare_graphs(baseline, Graph([], [replace(edge, start_match_by="name")]), exact=True).is_exact_match
    assert not compare_graphs(baseline, Graph([], [replace(edge, source_kind=None)]), exact=True).is_exact_match


def test_allowance_is_named_and_documented_and_does_not_hide_another_kind():
    allowance = PropertyAllowance("node", "MSSQL_Server", "last_seen", "A fresh conversion creates a new collection timestamp")
    before = Graph([node(last_seen="before", port=51433)], [])
    after = Graph([node(last_seen="after", port=51433)], [])
    report = compare_graphs(before, after, exact=True, allowances=[allowance])
    assert report.is_exact_match
    assert report.to_dict()["allowances"][0]["reason"] == allowance.reason
    assert not compare_graphs(before, Graph([node(last_seen="after", port=1433)], []), exact=True, allowances=[allowance]).is_exact_match
    other_before = Graph([Node("other", ["MSSQL_Login"], {"last_seen": "before"})], [])
    other_after = Graph([Node("other", ["MSSQL_Login"], {"last_seen": "after"})], [])
    assert not compare_graphs(other_before, other_after, exact=True, allowances=[allowance]).is_exact_match


def test_unordered_allowance_preserves_list_values_and_multiplicity():
    allowance = PropertyAllowance("node", "MSSQL_Server", "collectionSource", "These independently observed source tags have no ordering meaning", "unordered")
    baseline = Graph([node(collectionSource=["SQL", "LDAP"])], [])
    assert compare_graphs(baseline, Graph([node(collectionSource=["LDAP", "SQL"])], []), exact=True, allowances=[allowance]).is_exact_match
    assert not compare_graphs(baseline, Graph([node(collectionSource=["SQL"])], []), exact=True, allowances=[allowance]).is_exact_match
    with pytest.raises(ValueError, match="list"):
        compare_graphs(baseline, Graph([node(collectionSource="SQL")], []), exact=True, allowances=[allowance])


@pytest.mark.parametrize("kind,property,reason", [("*", "last_seen", "Reason"), ("MSSQL_Server", "*", "Reason"), ("MSSQL_Server", "port", "")])
def test_broad_or_unexplained_allowance_is_rejected(kind, property, reason):
    with pytest.raises(ValueError):
        PropertyAllowance("node", kind, property, reason)


def test_real_cli_exact_mode_checks_headers_and_writes_its_verdict(tmp_path, capsys):
    paths = []
    for name, label in (("baseline", "MSSQL_Base"), ("candidate", "OTHER")):
        path = tmp_path / name
        path.mkdir()
        (path / "graph.json").write_text(json.dumps({"metadata": {"source_kind": label}, "graph": {"nodes": [{"id": "N", "kinds": ["MSSQL_Server"], "properties": {"port": 51433}}], "edges": []}}), encoding="utf-8")
        paths.append(str(path))
    report_path = tmp_path / "report.json"
    assert cli.main([*paths, "--exact", "--json", str(report_path)]) == 1
    assert "graphs differ" in capsys.readouterr().out
    assert json.loads(report_path.read_text())["is_exact_match"] is False
    assert cli.main(paths) == 0  # The existing loss-only mode remains available.


def test_exact_cli_rejects_a_nonempty_directory_without_graph_payloads(tmp_path):
    directory = tmp_path / "empty"
    directory.mkdir()
    assert cli.main([str(directory), str(directory), "--exact", "--quiet"]) == 1
    assert cli.main([str(directory), str(directory), "--allowances", "unused.json"]) == 2
