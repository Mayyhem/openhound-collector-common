"""Unit tests for openhound_collector_common.orchestration.run (no live pipelines).

The orchestrator is exercised against a fake OpenHound-shaped object whose
preprocessor/converter just record how they were called, so these tests need
neither the openhound framework nor dlt installed.
"""
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from openhound_collector_common.orchestration import (
    StagePaths,
    derive_stage_paths,
    run_end_to_end,
)


def _fake_app(name="sccm"):
    """An OpenHound-shaped stand-in whose hooks append (stage, kwargs) to `calls`."""
    calls = []

    def preprocessor(**kwargs):
        calls.append(("preproc", kwargs))

    def converter(**kwargs):
        calls.append(("convert", kwargs))

    app = SimpleNamespace(name=name, preprocessor=preprocessor, converter=converter)
    return app, calls


def test_derive_stage_paths_matches_openhound_layout():
    app, _ = _fake_app(name="sccm")
    paths = derive_stage_paths(app, Path("/data/out"))
    assert paths == StagePaths(
        dataset_dir=Path("/data/out/sccm"),
        lookup_db=Path("/data/out/lookup.duckdb"),
        graph_out=Path("/data/out/graph"),
    )


def test_runs_preproc_then_convert_in_order():
    app, calls = _fake_app()
    run_end_to_end(app, Path("/data/out"), progress=None)
    assert [c[0] for c in calls] == ["preproc", "convert"]


def test_passes_derived_paths_to_each_stage():
    app, calls = _fake_app(name="sccm")
    run_end_to_end(app, Path("/data/out"), progress=None)
    preproc_kwargs = dict(calls[0][1])
    convert_kwargs = dict(calls[1][1])
    assert preproc_kwargs["input_path"] == Path("/data/out")
    assert preproc_kwargs["output_file"] == Path("/data/out/lookup.duckdb")
    assert convert_kwargs["input_path"] == Path("/data/out/sccm")
    assert convert_kwargs["output_path"] == Path("/data/out/graph")
    assert convert_kwargs["lookup_file"] == Path("/data/out/lookup.duckdb")


def test_none_progress_raw_to_preproc_but_shimmed_for_convert():
    app, calls = _fake_app()
    run_end_to_end(app, Path("/data/out"), progress=None)
    preproc_kwargs = dict(calls[0][1])
    convert_kwargs = dict(calls[1][1])
    # PreProcessor forwards the object straight to dlt.pipeline(), which accepts None.
    assert preproc_kwargs["progress"] is None
    # Converter reads progress.value, so None is wrapped in a .value=None shim.
    assert convert_kwargs["progress"] is not None
    assert convert_kwargs["progress"].value is None


def test_real_progress_passed_through_to_both_stages():
    app, calls = _fake_app()
    sentinel = SimpleNamespace(value="tqdm")  # stand-in for a framework Progress member
    run_end_to_end(app, Path("/data/out"), progress=sentinel)
    assert dict(calls[0][1])["progress"] is sentinel
    assert dict(calls[1][1])["progress"] is sentinel


def test_returns_derived_paths():
    app, _ = _fake_app(name="sccm")
    result = run_end_to_end(app, Path("/data/out"), progress=None)
    assert result == derive_stage_paths(app, Path("/data/out"))


def test_missing_preproc_hook_raises_before_running_anything():
    app, calls = _fake_app()
    app.preprocessor = None
    with pytest.raises(RuntimeError, match="preproc"):
        run_end_to_end(app, Path("/data/out"), progress=None)
    assert calls == []


def test_missing_convert_hook_raises_before_running_anything():
    app, calls = _fake_app()
    app.converter = None
    with pytest.raises(RuntimeError, match="convert"):
        run_end_to_end(app, Path("/data/out"), progress=None)
    assert calls == []


def test_convert_not_run_when_preproc_fails():
    calls = []

    def boom(**kwargs):
        calls.append(("preproc", kwargs))
        raise ValueError("preprocess exploded")

    def converter(**kwargs):
        calls.append(("convert", kwargs))

    app = SimpleNamespace(name="sccm", preprocessor=boom, converter=converter)
    with pytest.raises(ValueError, match="preprocess exploded"):
        run_end_to_end(app, Path("/data/out"), progress=None)
    assert [c[0] for c in calls] == ["preproc"]  # convert never reached


_NAME = "configmanbearpig_collection_20260730_101112.zip"  # a representative run-stamped name


def test_zip_graph_output_flat_bundles_json_under_given_name(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    for n in ("sccm_nodes-1.json", "mssql_edges-1.json", "ad_nodes-1.json"):
        (g / n).write_text('{"graph": {"nodes": [], "edges": []}}', encoding="utf-8")
    zp = zip_graph_output(g, _NAME)
    assert zp == g / _NAME
    with zipfile.ZipFile(zp) as zf:
        assert sorted(zf.namelist()) == ["ad_nodes-1.json", "mssql_edges-1.json", "sccm_nodes-1.json"]
    assert (g / "sccm_nodes-1.json").exists()  # loose files kept (non-destructive)


def test_zip_graph_output_default_name_is_opengraph_zip(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    (g / "sccm_nodes-1.json").write_text("{}", encoding="utf-8")
    assert zip_graph_output(g) == g / "opengraph.zip"  # collector-agnostic default


def test_zip_graph_output_skips_when_no_json(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    assert zip_graph_output(g, _NAME) is None
    assert not (g / _NAME).exists()
    # A missing dir is also a no-op (not an error).
    assert zip_graph_output(tmp_path / "nope", _NAME) is None


def test_zip_graph_output_excludes_nonjson_and_prior_zip(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    (g / "sccm_nodes-1.json").write_text("{}", encoding="utf-8")
    (g / "collect.log").write_text("noise", encoding="utf-8")
    (g / "configmanbearpig_collection_20260101_000000.zip").write_bytes(b"stale")  # a prior run's archive
    zp = zip_graph_output(g, _NAME)
    with zipfile.ZipFile(zp) as zf:
        assert zf.namelist() == ["sccm_nodes-1.json"]  # only json; not the log or the old zip


def test_run_end_to_end_zips_under_given_name(tmp_path):
    def preprocessor(**kwargs):
        pass

    def converter(**kwargs):
        out = kwargs["output_path"]  # the derived graph dir
        out.mkdir(parents=True, exist_ok=True)
        (out / "sccm_nodes-1.json").write_text('{"graph": {"nodes": [], "edges": []}}', encoding="utf-8")

    app = SimpleNamespace(name="sccm", preprocessor=preprocessor, converter=converter)
    paths = run_end_to_end(app, tmp_path, progress=None, graph_zip_name=_NAME)
    assert (paths.graph_out / _NAME).exists()


def test_run_end_to_end_defaults_zip_name_to_app_collection(tmp_path):
    def preprocessor(**kwargs):
        pass

    def converter(**kwargs):
        out = kwargs["output_path"]
        out.mkdir(parents=True, exist_ok=True)
        (out / "sccm_nodes-1.json").write_text("{}", encoding="utf-8")

    app = SimpleNamespace(name="sccm", preprocessor=preprocessor, converter=converter)
    paths = run_end_to_end(app, tmp_path, progress=None)
    assert (paths.graph_out / "sccm_collection.zip").exists()  # f"{app.name}_collection.zip"


# --- StagePaths.graph_zip: the archive that was written, not the one we expected ---
# The SCCM collector reports the upload artifact as the last line of its --run-all
# summary. Before this field it had to rebuild graph_out / <name it had asked for>
# and re-test existence, because run_end_to_end discarded zip_graph_output's return.

def _app_writing_graph(*filenames):
    """A fake app whose convert writes *filenames* into the derived graph dir."""
    def preprocessor(**kwargs):
        pass

    def converter(**kwargs):
        out = kwargs["output_path"]
        out.mkdir(parents=True, exist_ok=True)
        for name in filenames:
            (out / name).write_text('{"graph": {"nodes": [], "edges": []}}', encoding="utf-8")

    return SimpleNamespace(name="sccm", preprocessor=preprocessor, converter=converter)


def test_run_end_to_end_reports_the_archive_it_wrote(tmp_path):
    paths = run_end_to_end(
        _app_writing_graph("sccm_nodes-1.json"), tmp_path, progress=None, graph_zip_name=_NAME,
    )
    assert paths.graph_zip == paths.graph_out / _NAME
    assert paths.graph_zip.exists()  # the reported path is evidence, not a guess


def test_run_end_to_end_reports_the_default_named_archive(tmp_path):
    paths = run_end_to_end(_app_writing_graph("sccm_nodes-1.json"), tmp_path, progress=None)
    assert paths.graph_zip == paths.graph_out / "sccm_collection.zip"


def test_graph_zip_is_none_when_convert_emitted_no_json(tmp_path):
    """Nothing to bundle is a no-op, so there is no archive to report -- and a caller
    that reconstructs the path instead would print one that does not exist."""
    paths = run_end_to_end(_app_writing_graph(), tmp_path, progress=None, graph_zip_name=_NAME)
    assert paths.graph_zip is None
    assert not (paths.graph_out / _NAME).exists()


def test_derived_paths_report_no_archive():
    """derive_stage_paths runs before anything is written -- including on the failure
    path, where claiming an archive exists would be actively misleading."""
    app, _ = _fake_app(name="sccm")
    assert derive_stage_paths(app, Path("/data/out")).graph_zip is None


def test_the_three_derived_paths_remain_the_whole_constructor():
    """graph_zip defaults, so existing callers that build a StagePaths from the three
    derived locations keep working and compare equal to a freshly derived one."""
    app, _ = _fake_app(name="sccm")
    assert StagePaths(
        dataset_dir=Path("/data/out/sccm"),
        lookup_db=Path("/data/out/lookup.duckdb"),
        graph_out=Path("/data/out/graph"),
    ) == derive_stage_paths(app, Path("/data/out"))
