"""Prove a failed consumer can release bounded queues without a deadlock."""

from threading import Event, Thread

import pytest

from openhound_collector_common.dlt.source_bridge import CollectionStopped, StreamBridge


def test_cancel_releases_a_blocked_producer_and_keeps_buffered_rows():
    bridge = StreamBridge(["rows"], maxsize=1)
    bridge.put("rows", {"row": "saved before cancellation"})
    entered = Event()
    finished = Event()
    errors = []

    def produce():
        entered.set()
        try:
            bridge.put("rows", {"row": "blocked"})
        except CollectionStopped as error:
            errors.append(str(error))
        finally:
            finished.set()

    worker = Thread(target=produce, daemon=True)
    worker.start()
    assert entered.wait(timeout=1)
    assert not finished.is_set()
    bridge.cancel("Output file could not be written")
    assert finished.wait(timeout=2)
    worker.join(timeout=2)
    assert errors == ["Output file could not be written"]
    assert list(bridge.drain_stream("rows")) == [{"row": "saved before cancellation"}]
    bridge.broadcast_done()  # Also bounded after consumer cancellation.


def test_cancel_releases_an_empty_consumer_without_a_done_marker():
    bridge = StreamBridge(["rows"])
    result = []
    finished = Event()

    def consume():
        result.extend(bridge.drain_stream("rows"))
        finished.set()

    worker = Thread(target=consume, daemon=True)
    worker.start()
    bridge.cancel("The producer failed before sending rows")
    assert finished.wait(timeout=2)
    worker.join(timeout=2)
    assert result == []


def test_repeated_cancellation_retains_the_first_reason():
    bridge = StreamBridge(["rows"])
    bridge.cancel("First failure")
    bridge.cancel("Later cleanup")
    with pytest.raises(CollectionStopped, match="First failure"):
        bridge.put("rows", {})


def test_unknown_table_can_be_a_fatal_collector_contract_error():
    bridge = StreamBridge(["registered"], strict_tables=True)
    with pytest.raises(ValueError, match="Unregistered collection table"):
        bridge.put("misspelled", {})
    # Existing consumers retain the original warning-only choice by default.
    StreamBridge(["registered"]).put("misspelled", {})
