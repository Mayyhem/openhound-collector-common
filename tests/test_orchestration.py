"""Unit tests for openhound_collector_common.orchestration.run (no live pipelines).

The orchestrator is exercised against a fake OpenHound-shaped object whose
preprocessor/converter just record how they were called, so these tests need
neither the openhound framework nor dlt installed.
"""
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
