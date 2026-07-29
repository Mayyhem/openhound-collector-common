import json
import zipfile
from openhound_collector_common.integration_testing.graph import load_graph

PAYLOAD_A = {"graph": {"nodes": [
    {"id": "N1", "kinds": ["SCCM_Site", "Base"], "properties": {"siteCode": "PS1"}}],
    "edges": [{"kind": "SCCM_HasClient", "start": {"value": "N1"}, "end": {"value": "N2"},
               "properties": {"traversable": True}}]}}
PAYLOAD_B = {"graph": {"nodes": [
    {"id": "N2", "kinds": ["SCCM_ClientDevice"], "properties": {}}], "edges": []}}

def _write_dir(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(PAYLOAD_A), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(PAYLOAD_B), encoding="utf-8")
    return tmp_path

def test_load_from_directory(tmp_path):
    g = load_graph(_write_dir(tmp_path))
    assert len(g.nodes) == 2 and len(g.edges) == 1
    assert g.node("N1").properties["siteCode"] == "PS1"
    assert g.edges_of_kind("SCCM_HasClient")[0].start == "N1"
    assert g.edges_of_kind("SCCM_HasClient")[0].end == "N2"

def test_load_from_zip(tmp_path):
    d = _write_dir(tmp_path)
    zp = tmp_path / "payload.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.write(d / "a.json", "a.json")
        zf.write(d / "b.json", "b.json")
    g = load_graph(zp)
    assert len(g.nodes) == 2 and g.node("N2") is not None

def test_duplicate_node_id_merges(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"graph": {"nodes": [
        {"id": "X", "kinds": ["Computer"], "properties": {"a": 1, "b": None}}], "edges": []}}), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps({"graph": {"nodes": [
        {"id": "X", "kinds": ["Base"], "properties": {"b": 2}}], "edges": []}}), encoding="utf-8")
    g = load_graph(tmp_path)
    n = g.node("X")
    assert len(g.nodes) == 1
    assert set(n.kinds) == {"Computer", "Base"} and n.properties["a"] == 1 and n.properties["b"] == 2


def test_load_utf8_bom_payload(tmp_path):
    # ConfigManBearPig.ps1 writes JSON with a UTF-8 BOM; the loader must strip it
    # (utf-8-sig) so --compare-to-zip can consume CMBP zips.
    (tmp_path / "bom.json").write_bytes(
        b"\xef\xbb\xbf" + json.dumps(PAYLOAD_A).encode("utf-8"))
    g = load_graph(tmp_path)
    assert g.node("N1") is not None and g.node("N1").properties["siteCode"] == "PS1"
