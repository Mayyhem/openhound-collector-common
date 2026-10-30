"""Exercise recursive work, bounded workers and failure cleanup without a network."""

from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Event, Lock, Thread, get_ident

import pytest

from openhound_collector_common.clients.operations import ClientCleanupError
from openhound_collector_common.collection.engine import Phase, run_pipeline
from openhound_collector_common.collection.errors import FatalCollectionError
from openhound_collector_common.collection.registry import (
    TargetRegistry,
    matches_allowed_targets,
)
from openhound_collector_common.collection.scheduler import run_jobs
from openhound_collector_common.collection.work_queue import WorkQueue
from openhound_collector_common.dlt.source_bridge import StreamBridge


def test_caller_thread_mode_and_recursive_completion_callback():
    queue = WorkQueue()
    queue.submit("root")
    caller = get_ident()

    def complete(target):
        assert queue.in_flight() == 1
        if target == "root":
            queue.submit("child")

    results = run_jobs(
        queue, lambda target: (target, get_ident()), 0, on_target_complete=complete
    )
    assert results == [("root", ("root", caller)), ("child", ("child", caller))]
    assert queue.in_flight() == 0


def test_large_target_list_submits_only_one_loop_per_worker(monkeypatch):
    import openhound_collector_common.collection.scheduler as scheduler

    submitted = []

    class CountingExecutor(ThreadPoolExecutor):
        def submit(self, function, *args, **kwargs):
            submitted.append(function)
            return super().submit(function, *args, **kwargs)

    monkeypatch.setattr(scheduler, "ThreadPoolExecutor", CountingExecutor)
    queue = WorkQueue()
    for index in range(500):
        queue.submit(f"host{index}")
    results = run_jobs(queue, str.upper, 3)
    assert len(results) == 500
    assert len(submitted) == 3
    assert (
        len({target for target, result in results if result == target.upper()}) == 500
    )


def test_failure_stops_pending_targets_but_waits_for_active_cleanup():
    queue = WorkQueue()
    for name in ("active", "broken", "pending"):
        queue.submit(name)
    active_started, allow_cleanup, failure_seen, returned = (Event() for _ in range(4))
    errors = []
    original = ClientCleanupError("Illustrative cleanup failure")

    def collect(target):
        if target == "active":
            active_started.set()
            assert allow_cleanup.wait(5)
            return "cleaned up"
        assert active_started.wait(5)
        raise original

    def run():
        try:
            run_jobs(queue, collect, 2, on_failure=lambda error: failure_seen.set())
        except BaseException as error:
            errors.append(error)
        finally:
            returned.set()

    thread = Thread(target=run)
    thread.start()
    try:
        assert failure_seen.wait(5)
        assert not returned.is_set()
        assert queue.unstarted_targets() == ("pending",)
    finally:
        allow_cleanup.set()
        thread.join(5)
    assert not thread.is_alive()
    assert errors == [original]
    assert queue.in_flight() == 0


def test_callback_failure_preserves_original_even_when_failure_callback_fails():
    queue = WorkQueue()
    queue.submit("host")
    original = RuntimeError("Completion callback failed")

    def complete(target):
        raise original

    def fail(error):
        raise ValueError("Secondary failure")

    with pytest.raises(RuntimeError) as captured:
        run_jobs(queue, str.upper, 1, on_target_complete=complete, on_failure=fail)
    assert captured.value is original
    assert queue.in_flight() == 0


def test_next_failure_notifies_before_joining_a_blocked_peer():
    entered = Event()
    released = Event()
    original = RuntimeError("Queue could not supply work")
    guard = Lock()
    calls = []

    class BrokenQueue(WorkQueue):
        def next(self):
            with guard:
                first = not calls
                calls.append(True)
            if first:
                return super().next()
            assert entered.wait(5)
            raise original

    queue = BrokenQueue()
    queue.submit("active")

    def collect(target):
        entered.set()
        assert released.wait(5)

    with pytest.raises(RuntimeError) as captured:
        run_jobs(queue, collect, 2, on_failure=lambda error: released.set())
    assert captured.value is original


def test_cancel_releases_full_output_queue_and_closes_phase_generator():
    queue = WorkQueue()
    queue.submit("producing")
    queue.submit("broken")
    bridge = StreamBridge(["rows"], maxsize=1)
    producing, closed = Event(), Event()
    original = ClientCleanupError("Cleanup could not be confirmed")

    def phase(target, context):
        if target == "broken":
            assert producing.wait(5)
            raise original
        try:
            yield "rows", {"first": True}
            producing.set()
            yield "rows", {"second": True}
        finally:
            closed.set()

    with pytest.raises(ClientCleanupError) as captured:
        run_pipeline(
            queue,
            None,
            [Phase("read", ("rows",), phase)],
            bridge.streams,
            2,
            emit=bridge.put,
            finish=bridge.broadcast_done,
            on_failure=lambda error: bridge.cancel("A worker failed"),
        )
    assert captured.value is original
    assert closed.is_set()
    assert queue.in_flight() == 0
    assert list(bridge.drain_stream("rows")) == [{"first": True}]


def test_explicit_stop_and_invalid_completion_cannot_report_success():
    queue = WorkQueue()
    queue.submit("host")
    queue.stop("The caller requested a stop")
    with pytest.raises(FatalCollectionError, match="caller requested"):
        run_jobs(queue, str.upper, 0)
    with pytest.raises(ValueError, match="inactive"):
        queue.complete("host")
    assert queue.in_flight() == 0
    assert not queue.submit("late")


def test_registry_keeps_aliases_but_never_invents_endpoint_merges():
    registry = TargetRegistry[str]()
    registry.bind_identity("S-1-5-21-example", "record")
    registry.bind_alias("short", "record")
    registry.bind_alias("short.example.com", "record")
    registry.bind_alias("short:51433", "other record")
    assert registry.find("S-1-5-21-example", "unknown") == "record"
    assert registry.find(None, "SHORT") == "record"
    assert registry.find(None, "short:51433") == "other record"
    assert registry.find(None, "short\\instance") is None
    assert registry.snapshot(str) == ["record", "other record"]
    assert matches_allowed_targets({"short:51433"}, ["SHORT:51433"])
    assert not matches_allowed_targets({"short:51433"}, ["short:1433"])
    assert matches_allowed_targets(set(), ["anything"])


def test_bad_worker_count_still_finishes_phase_streams():
    finished = []
    with pytest.raises(ValueError):
        run_pipeline(
            WorkQueue(),
            None,
            [],
            {"rows": Queue()},
            0,
            finish=lambda: finished.append(True),
        )
    assert finished == [True]
