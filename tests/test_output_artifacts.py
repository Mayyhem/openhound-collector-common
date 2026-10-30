"""Cleanup must retain evidence and never traverse outside the named output root."""

import os
import subprocess

import pytest

from openhound_collector_common.orchestration.artifacts import (
    OutputCleanupError,
    clean_previous_collection,
    prior_load_packages,
)
from openhound_collector_common.orchestration.commands import (
    cli_path_arg,
    continuation_commands,
)


def clean(output, requested):
    clean_previous_collection(
        output,
        requested,
        dataset_name="example",
        artifact_names=("example", "lookup.duckdb", "graph"),
    )


def test_warn_then_clean_keeps_logs_and_reports(tmp_path, caplog):
    loads = tmp_path / "example" / "_dlt_loads"
    loads.mkdir(parents=True)
    (loads / "one.jsonl").write_text("{}")
    (tmp_path / "lookup.duckdb").write_text("old")
    (tmp_path / "graph").mkdir()
    (tmp_path / "collect_full_old.log").write_text("old evidence")
    (tmp_path / "compare-old.json").write_text("{}")
    assert prior_load_packages(tmp_path, "example")[0] == 1
    clean(tmp_path, False)
    assert "1 dlt load package(s)" in caplog.text
    assert "oldest written" in caplog.text
    assert (tmp_path / "lookup.duckdb").exists()
    clean(tmp_path, True)
    assert {path.name for path in tmp_path.iterdir()} == {
        "collect_full_old.log",
        "compare-old.json",
    }


def test_all_resolved_paths_are_checked_before_any_removal(tmp_path):
    root = tmp_path / "output"
    root.mkdir()
    (root / "first").write_text("keep")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    alias = root / "alias"
    if os.name == "nt":
        # A junction requires no Windows symlink privilege. Both paths belong
        # to this test; this command only creates the link and deletes nothing.
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(outside)],
            check=True,
            capture_output=True,
        )
    else:
        alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OutputCleanupError, match="outside"):
        clean_previous_collection(
            root, True, dataset_name="example", artifact_names=("first", "alias")
        )
    assert (root / "first").read_text() == "keep"
    assert (outside / "keep").read_text() == "keep"


@pytest.mark.parametrize("name", ["..", "../outside", ".", ""])
def test_cleanup_rejects_unsafe_declared_artifacts(tmp_path, name):
    with pytest.raises(OutputCleanupError):
        clean_previous_collection(
            tmp_path, True, dataset_name="example", artifact_names=(name,)
        )


def test_cleanup_failure_is_visible_and_aborts(tmp_path, monkeypatch, caplog):
    (tmp_path / "example").mkdir()

    def fail(path):
        raise OSError("file is locked")

    monkeypatch.setattr(
        "openhound_collector_common.orchestration.artifacts.shutil.rmtree", fail
    )
    with pytest.raises(OutputCleanupError, match="--clean could not remove"):
        clean(tmp_path, True)
    assert "file is locked" in caplog.text


def test_continuation_paths_have_no_placeholders_and_keep_space_paths_together(
    tmp_path,
):
    output = tmp_path / "saved collection"
    prepare, convert = continuation_commands("example", output)
    assert cli_path_arg(output) in prepare
    assert cli_path_arg(output / "example") in convert
    assert cli_path_arg(output / "lookup.duckdb") in prepare
    assert "--lookup-file " + cli_path_arg(output / "lookup.duckdb") in convert
    if os.name == "nt":
        assert cli_path_arg(output) == f'"{output}"'
        assert (
            cli_path_arg(output / "$value;it's")
            == "'" + str(output / "$value;it's").replace("'", "''") + "'"
        )
