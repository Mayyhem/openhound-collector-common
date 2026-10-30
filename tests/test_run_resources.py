"""Use injected measurements and small owned files; never stress real memory/disk."""

from pathlib import Path
from threading import Event
import sys
import shutil
import zipfile

import pytest

from openhound_collector_common.orchestration.resources import (
    ResourceLimitReached,
    RunResources,
    parse_byte_size,
)
from openhound_collector_common.orchestration.scratch import private_scratch
from openhound_collector_common.orchestration.run import zip_graph_output
from openhound_collector_common.graph.files import GraphFileWriter
import json


@pytest.mark.parametrize(
    "text,expected",
    [
        ("1GB", 1_000_000_000),
        ("1GiB", 1_073_741_824),
        ("1.5MB", 1_500_000),
        ("2 KiB", 2048),
        ("1B", 1),
        ("17", 17),
    ],
)
def test_explicit_decimal_and_binary_units(text, expected):
    assert parse_byte_size(text) == expected


@pytest.mark.parametrize("text", ["", "0", "-1GB", "1XB", "NaN", "0.5B", "1GB garbage"])
def test_invalid_limits_are_rejected(text):
    with pytest.raises(ValueError):
        parse_byte_size(text)


def test_only_new_or_changed_owned_files_count_and_overlaps_count_once(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    old = raw / "old.json"
    old.write_bytes(b"old" * 100)
    resources = RunResources(stop_event=Event(), memory_reader=lambda: 10)
    resources.register_path(raw)
    (raw / "new.json").write_bytes(b"12345")
    child = raw / "child"
    child.mkdir()
    (child / "nested.json").write_bytes(b"123")
    (raw / "full.log").write_bytes(b"1234")
    (raw / "graph.zip").write_bytes(b"12")
    resources.register_path(child)
    resources.register_path(raw)
    snapshot = resources.sample()
    assert snapshot.data_bytes == 8
    assert snapshot.log_bytes == 4 and snapshot.archive_bytes == 2
    old.write_bytes(b"replacement")
    assert resources.sample().data_bytes == 8 + len(b"replacement")


def test_saved_stage_can_explicitly_adopt_existing_verified_data(tmp_path):
    (tmp_path / "raw.json").write_bytes(b"123")
    resources = RunResources(stop_event=Event(), memory_reader=lambda: 10)
    resources.register_path(tmp_path, include_existing=True)
    assert resources.sample().data_bytes == 3


def test_limit_is_sticky_and_peak_survives_scratch_cleanup(tmp_path):
    stopped = Event()
    resources = RunResources(
        stop_event=stopped, max_data_bytes=5, memory_reader=lambda: 10
    )
    sibling = tmp_path / "keep.txt"
    sibling.write_text("keep", encoding="utf-8")
    with private_scratch(
        prefix="test-", parent=tmp_path, resources=resources
    ) as scratch:
        (scratch / "data.json").write_bytes(b"123456")
        with pytest.raises(ResourceLimitReached):
            resources.check(sample_now=True)
        assert stopped.is_set()
    assert not scratch.exists()
    assert sibling.read_text(encoding="utf-8") == "keep"
    snapshot = resources.sample()
    assert snapshot.data_bytes == 0 and snapshot.peak_data_bytes == 6
    assert resources.stop_category == "data"
    with pytest.raises(ResourceLimitReached):
        resources.check()


def test_system_memory_threshold_signals_without_consuming_real_memory():
    stopped = Event()
    with RunResources(
        stop_event=stopped, memory_threshold=90, memory_reader=lambda: 91
    ) as resources:
        assert stopped.is_set()
        assert resources.stop_category == "memory"
        with pytest.raises(ResourceLimitReached):
            resources.check()
    assert not resources._thread.is_alive()


def test_background_measurement_failure_stops_work_and_cannot_look_successful():
    calls = []
    original = OSError("Illustrative measurement failure")

    def read_memory():
        calls.append(True)
        if len(calls) > 1:
            raise original
        return 10

    stopped = Event()
    with pytest.raises(RuntimeError) as captured:
        with RunResources(
            stop_event=stopped, sample_seconds=0.01, memory_reader=read_memory
        ):
            assert stopped.wait(2)
    assert captured.value.__cause__ is original


def test_linked_output_path_cannot_escape_accounting(tmp_path, monkeypatch):
    linked = tmp_path / "linked"
    linked.mkdir()
    original = Path.is_junction
    monkeypatch.setattr(
        Path, "is_junction", lambda path: path == linked or original(path)
    )
    resources = RunResources(stop_event=Event(), memory_reader=lambda: 10)
    with pytest.raises(OSError, match="linked"):
        resources.register_path(tmp_path)


def test_stage_failure_cleans_only_its_owned_scratch(tmp_path):
    sibling = tmp_path / "keep.txt"
    sibling.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="stage failed"):
        with private_scratch(prefix="test-", parent=tmp_path) as owned:
            (owned / "intermediate").write_bytes(b"some temporary data")
            raise ValueError("stage failed")
    assert not owned.exists() and sibling.exists()


@pytest.mark.parametrize("log_first", [True, False])
def test_current_log_spools_are_separate_even_when_names_have_no_extension(
    tmp_path, log_first
):
    spool = tmp_path / "logs"
    spool.mkdir()
    (spool / "buffer").write_bytes(b"12345")
    resources = RunResources(stop_event=Event(), memory_reader=lambda: 10)
    roots = [(spool, "logs"), (tmp_path, "data")]
    for path, category in roots if log_first else reversed(roots):
        resources.register_path(path, include_existing=True, category=category)
    assert resources.sample().log_bytes == 5
    assert resources.snapshot.data_bytes == 0


def test_owned_interrupt_is_requested_once_and_cannot_run_after_scope():
    usage = [10]
    calls = []
    resources = RunResources(
        stop_event=Event(), memory_threshold=90, memory_reader=lambda: usage[0]
    )
    with resources.interruptible("owned calculation", lambda: calls.append("stop")):
        # Capture the already queued callback to reproduce a delayed monitor.
        queued = next(iter(resources._interrupts.values()))[1]
        usage[0] = 91
        resources.sample()
        resources.sample()
    queued()
    assert calls == ["stop"]


def test_failed_interrupt_is_a_failure_even_when_a_normal_limit_was_reached():
    usage = [10]
    resources = RunResources(
        stop_event=Event(), memory_threshold=90, memory_reader=lambda: usage[0]
    )

    def fail():
        raise OSError("Owned interruption failed")

    with pytest.raises(RuntimeError, match="measurements failed"):
        with resources:
            with resources.interruptible("calculation", fail):
                usage[0] = 91
                resources.sample()
                raise ResourceLimitReached(resources.stop_reason)


def test_graph_stop_publishes_complete_current_records_and_skips_archive(tmp_path):
    graph = tmp_path / "graph"
    with GraphFileWriter(graph, {"example": "Example"}, batch_size=1) as writer:
        writer.write_node("example", {"id": "old"})
        writer.write_node("example", {"id": "old-part-two"})
    resources = RunResources(
        stop_event=Event(), max_data_bytes=1, memory_reader=lambda: 10
    )
    with pytest.raises(ResourceLimitReached):
        with GraphFileWriter(
            graph, {"example": "Example"}, batch_size=1, resources=resources
        ) as writer:
            writer.write_node("example", {"id": "complete"})
            writer.write_node("example", {"id": "never-accepted"})
    documents = [json.loads(path.read_text()) for path in graph.glob("*.json")]
    assert [
        node["id"] for document in documents for node in document["graph"]["nodes"]
    ] == ["complete"]
    with pytest.raises(ResourceLimitReached):
        zip_graph_output(graph, resources=resources)
    assert not list(graph.glob("*.zip*"))
    assert not list(graph.glob(".graph-write-*"))


def test_archive_stop_retains_loose_files_old_archive_and_removes_only_owned_temp(
    tmp_path, monkeypatch
):
    data = tmp_path / "nodes.json"
    data.write_bytes(b"x" * (1024 * 1024 + 1))
    archive = tmp_path / "graph.zip"
    archive.write_bytes(b"previous complete archive")
    sibling = tmp_path / ".archive-other.zip.tmp"
    sibling.write_bytes(b"unrelated")
    usage = [10]
    resources = RunResources(
        stop_event=Event(), memory_threshold=90, memory_reader=lambda: usage[0]
    )
    original = zipfile._ZipWriteFile.write

    def write_then_stop(destination, chunk):
        result = original(destination, chunk)
        usage[0] = 91
        resources.sample()
        return result

    monkeypatch.setattr(zipfile._ZipWriteFile, "write", write_then_stop)
    with pytest.raises(ResourceLimitReached):
        zip_graph_output(tmp_path, "graph.zip", resources=resources)
    assert archive.read_bytes() == b"previous complete archive"
    assert data.stat().st_size == 1024 * 1024 + 1
    assert list(tmp_path.glob(".archive-*.zip.tmp")) == [sibling]


def test_finished_archive_is_reported_separately_from_its_loose_files(tmp_path):
    resources = RunResources(stop_event=Event(), memory_reader=lambda: 10)
    resources.register_path(tmp_path)
    (tmp_path / "nodes.json").write_text('{"graph":{"nodes":[],"edges":[]}}')
    archive = zip_graph_output(tmp_path, resources=resources)
    assert archive is not None
    assert resources.snapshot.archive_bytes == archive.stat().st_size
    assert resources.snapshot.data_bytes == (tmp_path / "nodes.json").stat().st_size
    with zipfile.ZipFile(archive) as saved:
        assert saved.read("nodes.json") == (tmp_path / "nodes.json").read_bytes()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows open-file deletion policy")
def test_windows_locked_scratch_reports_cleanup_failure_and_keeps_siblings(tmp_path):
    sibling = tmp_path / "keep.txt"
    sibling.write_text("keep")
    stream = None
    try:
        with pytest.raises(PermissionError):
            with private_scratch(prefix="locked-", parent=tmp_path) as owned:
                stream = (owned / "open-file").open("wb")
                stream.write(b"private scratch")
                stream.flush()
        assert sibling.read_text() == "keep"
    finally:
        if stream is not None:
            stream.close()
        # This test owns exactly the verified new child and can now release it.
        assert owned.parent == tmp_path.resolve()
        shutil.rmtree(owned)
