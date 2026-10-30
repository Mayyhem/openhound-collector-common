"""Validate unmerged graph files, including legitimate distinct login mappings."""

import json
import zipfile

import pytest

from openhound_collector_common.integration_testing.graph import load_graph
from openhound_collector_common.integration_testing.raw_checks import GraphValidationError, parse_checked_payloads


def node(**properties):
    return {"id": "N", "kinds": ["MSSQL_Login"], "properties": properties}


def edge(login="first"):
    return {"kind": "MSSQL_LinkedTo", "start": {"value": "N"}, "end": {"value": "R"}, "properties": {"localLogin": login}}


def payload(nodes=(), edges=()):
    return json.dumps({"graph": {"nodes": list(nodes), "edges": list(edges)}})


def test_conflicting_node_properties_are_found_before_merge(tmp_path):
    directory = tmp_path / "graph"
    directory.mkdir()
    (directory / "first.json").write_text(payload([node(owner="first")]), encoding="utf-8")
    (directory / "second.json").write_text(payload([node(owner="second")]), encoding="utf-8")
    # The ordinary loader's convenience merge would keep the first owner.
    assert load_graph(directory).node("N").properties["owner"] == "first"
    with pytest.raises(GraphValidationError, match="contradicts property 'owner'"):
        load_graph(directory, validate_raw=True)


def test_complementary_node_properties_and_distinct_mappings_are_valid():
    result = parse_checked_payloads([("first.json", payload([node(name="login")], [edge("first")])), ("second.json", payload([node(enabled=True)], [edge("second")]))])
    assert len(result) == 2


def test_identical_repeated_relationships_are_rejected():
    with pytest.raises(GraphValidationError, match="duplicates an identical record"):
        parse_checked_payloads([("graph.json", payload(edges=[edge(), edge()]))])


@pytest.mark.parametrize("text", ['{"graph":{"nodes":[],"nodes":[]}}', '{"report": "this is not a graph"}', '{"graph": {}}', '{"graph":{"nodes": {}}}', payload([{"id": 42, "kinds": ["Computer"]}]), payload([{"id": "N", "kinds": ["Computer", "Computer"]}]), payload(edges=[{"kind": "MemberOf", "start": {}, "end": {"value": "G"}}])])
def test_malformed_or_non_graph_files_cannot_look_like_an_empty_graph(text):
    with pytest.raises(GraphValidationError):
        parse_checked_payloads([("bad.json", text)])


def test_zip_files_are_checked_before_the_same_node_merge(tmp_path):
    archive = tmp_path / "graph.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("first.json", payload([node(owner=False)]))
        output.writestr("second.json", payload([node(owner=0)]))
    with pytest.raises(GraphValidationError, match="contradicts"):
        load_graph(archive, validate_raw=True)


def test_explicit_empty_graph_is_valid():
    assert parse_checked_payloads([("empty.json", payload())])
