"""Raw file labels, complete batches, failures, and owned-file replacement."""

import json
from pathlib import Path

import pytest

from openhound_collector_common.graph.files import GraphFileWriter


def node(identifier):
    return {"id": identifier, "kinds": ["Example"], "properties": {"name": identifier}}


def documents(output):
    return [
        json.loads(path.read_text(encoding="utf-8")) for path in output.glob("*.json")
    ]


def test_batches_keep_every_record_and_file_source_without_global_state(tmp_path):
    with GraphFileWriter(tmp_path, {"custom": "Example", "ad": None}) as writer:
        for number in range(1001):
            writer.write_node("custom", node(str(number)))
        writer.write_node("ad", {**node("sid"), "kinds": ["User", "Base"]})
        writer.write_edge(
            "ad",
            {
                "kind": "Example_Link",
                "start": {"value": "sid", "match_by": "id"},
                "end": {"value": "0", "match_by": "id"},
                "properties": {
                    "collectionSource": ["LDAP", "SQL"],
                    "traversable": False,
                },
            },
        )
    docs = documents(tmp_path)
    custom = [doc for doc in docs if "metadata" in doc]
    native = [doc for doc in docs if "metadata" not in doc]
    assert {doc["metadata"]["source_kind"] for doc in custom} == {"Example"}
    assert [len(doc["graph"]["nodes"]) for doc in custom if doc["graph"]["nodes"]] == [
        1000,
        1,
    ]
    assert {n["id"] for doc in custom for n in doc["graph"]["nodes"]} == {
        str(n) for n in range(1001)
    }
    assert [n["id"] for doc in native for n in doc["graph"]["nodes"]] == ["sid"]
    assert [e["properties"] for doc in native for e in doc["graph"]["edges"]] == [
        {"collectionSource": ["LDAP", "SQL"], "traversable": False}
    ]
    assert writer.node_count == 1002
    assert writer.edge_count == 1


def test_absent_properties_are_omitted_without_losing_false_empty_or_array_order(
    tmp_path,
):
    with GraphFileWriter(tmp_path, {"example": "Example"}) as writer:
        writer.write_node(
            "example",
            {
                **node("one"),
                "icon": None,
                "properties": {
                    "missing": None,
                    "disabled": False,
                    "count": 0,
                    "empty": [],
                    "ordered": ["z", "a"],
                    "assumed": True,
                    "assumptionBasis": "Observed input",
                },
            },
        )
    actual = next(n for doc in documents(tmp_path) for n in doc["graph"]["nodes"])
    assert "icon" not in actual
    assert actual["properties"] == {
        "disabled": False,
        "count": 0,
        "empty": [],
        "ordered": ["z", "a"],
        "assumed": True,
        "assumptionBasis": "Observed input",
    }


def test_replacement_retires_only_previous_owned_parts_and_handles_empty_results(
    tmp_path,
):
    with GraphFileWriter(tmp_path, {"example": "Example"}, batch_size=1) as writer:
        writer.write_node("example", node("one"))
        writer.write_node("example", node("two"))
    unrelated = tmp_path / "other.json"
    unrelated.write_text("keep me", encoding="utf-8")
    with GraphFileWriter(tmp_path, {"example": "Example"}):
        pass
    assert unrelated.read_text(encoding="utf-8") == "keep me"
    files = list(tmp_path.glob("example_*.json"))
    assert len(files) == 2
    assert all(
        json.loads(file.read_text())["graph"] == {"nodes": [], "edges": []}
        for file in files
    )
    assert not list(tmp_path.glob(".graph-write-*"))


def test_failure_before_publication_preserves_complete_previous_files(tmp_path, caplog):
    with GraphFileWriter(tmp_path, {"example": "Example"}) as writer:
        writer.write_node("example", node("previous"))
    before = {p.name: p.read_bytes() for p in tmp_path.glob("*.json")}
    with pytest.raises(RuntimeError, match="model failed"):
        with GraphFileWriter(tmp_path, {"example": "Example"}, batch_size=1) as writer:
            writer.write_node("example", node("new"))
            raise RuntimeError("model failed")
    assert {p.name: p.read_bytes() for p in tmp_path.glob("*.json")} == before
    assert "staged files were not published" in caplog.text
    assert not list(tmp_path.glob(".graph-write-*"))


def test_manifest_cannot_retire_a_file_outside_its_owned_prefix(tmp_path):
    keep = tmp_path / "keep.json"
    keep.write_text("keep", encoding="utf-8")
    directory = tmp_path / ".openhound-files"
    directory.mkdir()
    (directory / "example.json").write_text('["../keep.json"]', encoding="utf-8")
    with pytest.raises(ValueError, match="ownership manifest"):
        with GraphFileWriter(tmp_path, {"example": "Example"}) as writer:
            writer.write_node("example", node("new"))
    assert keep.read_text(encoding="utf-8") == "keep"
    assert not list(tmp_path.glob("example_*.json"))


def test_publication_failure_is_fatal_and_visible(tmp_path, monkeypatch, caplog):
    original = Path.replace

    def fail_publish(path, target):
        if Path(target).name == "example_nodes-0001.json":
            raise OSError("test disk failure")
        return original(path, target)

    monkeypatch.setattr(Path, "replace", fail_publish)
    with pytest.raises(OSError, match="disk failure"):
        with GraphFileWriter(tmp_path, {"example": None}) as writer:
            writer.write_node("example", node("new"))
    assert "conversion is incomplete" in caplog.text


@pytest.mark.parametrize(
    "sources,batch_size",
    [
        ({}, 1),
        ({"../escape": None}, 1),
        ({"example": ""}, 1),
        ({"example": None}, 0),
        ({"example": None}, True),
    ],
)
def test_invalid_output_settings_are_rejected(tmp_path, sources, batch_size):
    with pytest.raises(ValueError):
        GraphFileWriter(tmp_path, sources, batch_size=batch_size)
