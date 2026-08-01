import json

from openhound_collector_common.integration_testing import cli


def _payload(path, nodes):
    path.write_text(json.dumps({"graph": {"nodes": nodes, "edges": []}}), encoding="utf-8")


def _dir_with(tmp_path, name, nodes):
    d = tmp_path / name
    d.mkdir()
    _payload(d / "sccm_nodes.json", nodes)
    return d


N1 = [{"id": "N1", "kinds": ["SCCM_Site"], "properties": {"siteCode": "PS1"}}]
N1_N2 = N1 + [{"id": "N2", "kinds": ["SCCM_Site"], "properties": {}}]


def test_clean_comparison_exits_zero(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1)
    b = _dir_with(tmp_path, "candidate", N1)
    assert cli.main([str(a), str(b)]) == 0
    assert "RESULT: 0 regressions" in capsys.readouterr().out


def test_dropped_node_exits_one(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1_N2)
    b = _dir_with(tmp_path, "candidate", N1)
    assert cli.main([str(a), str(b)]) == 1
    assert "N2" in capsys.readouterr().out


def test_added_node_exits_zero(tmp_path):
    a = _dir_with(tmp_path, "baseline", N1)
    b = _dir_with(tmp_path, "candidate", N1_N2)
    assert cli.main([str(a), str(b)]) == 0


def test_json_report_is_written(tmp_path):
    a = _dir_with(tmp_path, "baseline", N1_N2)
    b = _dir_with(tmp_path, "candidate", N1)
    out = tmp_path / "diff.json"
    assert cli.main([str(a), str(b), "--json", str(out)]) == 1
    assert json.loads(out.read_text())["nodes_only_in_baseline"] == ["N2"]


def test_quiet_suppresses_the_report_but_not_the_exit_code(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1_N2)
    b = _dir_with(tmp_path, "candidate", N1)
    assert cli.main([str(a), str(b), "-q"]) == 1
    assert capsys.readouterr().out == ""


def test_bad_path_exits_two(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1)
    missing = tmp_path / "nope.txt"
    missing.write_text("not a payload", encoding="utf-8")
    assert cli.main([str(a), str(missing)]) == 2
    assert "openhound-compare:" in capsys.readouterr().err


def test_zip_against_directory(tmp_path):
    """Both sides accept either shape -- an archived baseline vs a fresh convert dir."""
    import zipfile
    zp = tmp_path / "baseline.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("nodes.json", json.dumps({"graph": {"nodes": N1_N2, "edges": []}}))
    cand = _dir_with(tmp_path, "candidate", N1)
    assert cli.main([str(zp), str(cand), "-q"]) == 1
