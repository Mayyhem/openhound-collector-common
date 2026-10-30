"""Ownership survives interleaved writes without modifying source records."""

import pytest

from openhound_collector_common.collection import RunDescription, TargetRowWriter
from openhound_collector_common.dlt.source_bridge import StreamBridge


def test_interleaved_targets_keep_their_own_rows_and_do_not_change_inputs():
    bridge = StreamBridge(["principals"])
    first = TargetRowWriter(bridge, run_id="run", target_id="first:1433")
    second = TargetRowWriter(bridge, run_id="run", target_id="second:51433")
    original = {"principal_id": 1, "name": "same-name"}
    first.put("principals", original)
    second.put("principals", original)
    bridge.broadcast_done()
    rows = list(bridge.drain_stream("principals"))
    assert [row["collection_target_id"] for row in rows] == [
        "first:1433",
        "second:51433",
    ]
    assert {row["collection_run_id"] for row in rows} == {"run"}
    assert original == {"principal_id": 1, "name": "same-name"}


@pytest.mark.parametrize("field", ["collection_target_id", "collection_run_id"])
def test_conflicting_reserved_fields_are_rejected_before_a_row_is_queued(field):
    bridge = StreamBridge(["principals"])
    writer = TargetRowWriter(bridge, run_id="run", target_id="first")
    with pytest.raises(ValueError, match="conflicting reserved field"):
        writer.put("principals", {field: "another-owner"})
    assert bridge.streams["principals"].empty()


def test_saved_choices_round_trip_as_flat_rows():
    original = RunDescription(
        "run", {"skip_nodes": True, "methods": ["LDAP"], "limit": 10}
    )
    row = original.as_row()
    assert isinstance(row["settings_json"], str)
    restored = RunDescription.from_row(row)
    assert restored == original


@pytest.mark.parametrize("version", [None, 0, 2, "1"])
def test_unknown_saved_format_requires_recollection(version):
    row = {
        "collection_format_version": version,
        "collection_run_id": "run",
        "settings_json": "{}",
    }
    with pytest.raises(ValueError, match="recollect"):
        RunDescription.from_row(row)


@pytest.mark.parametrize("encoded", ["[]", "null", '{"choice": {}}', '{"choice": [1]}'])
def test_loaded_settings_reject_shapes_the_writer_would_not_save(encoded):
    row = {
        "collection_format_version": 1,
        "collection_run_id": "run",
        "settings_json": encoded,
    }
    with pytest.raises(ValueError):
        RunDescription.from_row(row)
