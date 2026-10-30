"""Check actual thread cleanup, partial results and shared-host credential ownership."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event, get_ident
from types import SimpleNamespace
import time

import pytest

from openhound_collector_common.clients import wmi, wmi_session
from openhound_collector_common.clients.operations import (
    ClientCleanupError,
    ReadControl,
    ReadStoppedError,
)
from openhound_collector_common.clients.deadline import Deadline
from openhound_collector_common.clients.wmi_session import WmiHostLease
from wmi_inprocess_fixtures import install_provider


class ControlledBackend:
    """A read returns one row, then stays active until its own stop request."""

    operation = None

    def __init__(self):
        self.stop = Event()
        self.closed = False
        self.owner_threads = []

    def connect(self):
        self.owner_threads.append(get_ident())

    def execquery(self, namespace, query):
        return None

    def stream(self, raw):
        yield {"complete": True}
        assert self.stop.wait(2), "The operation monitor did not request cancellation"
        self.owner_threads.append(get_ident())
        self.operation.check()

    def interrupt(self):
        self.stop.set()

    def close(self):
        self.owner_threads.append(get_ident())
        self.closed = True


def test_expired_read_retains_complete_rows_and_waits_for_provider_cleanup(monkeypatch):
    provider = ControlledBackend()
    client = wmi.WmiClient("illustrative-host", read_control=ReadControl(0.1))
    monkeypatch.setattr(client, "_build_backend", lambda mode: provider)
    with ThreadPoolExecutor(max_workers=1) as workers:
        rows = workers.submit(client.query, "illustrative-query").result(timeout=3)
    assert rows == [{"complete": True}]
    assert provider.closed
    assert len(set(provider.owner_threads)) == 1
    assert client.last_query_result.state == "failed"
    assert client.last_query_result.row_count is None
    assert client._backend is None


def test_stop_before_start_submits_no_authentication(monkeypatch):
    stop = Event()
    stop.set()
    client = wmi.WmiClient(
        "illustrative-host", read_control=ReadControl(1, stop_event=stop)
    )
    monkeypatch.setattr(
        client,
        "_build_backend",
        lambda mode: pytest.fail("Authentication started after stop"),
    )
    assert client.query("query") == []
    assert client.last_query_result.state == "failed"


def test_cleanup_failure_is_fatal_even_when_the_read_was_already_stopped(monkeypatch):
    provider = ControlledBackend()
    provider.close = lambda: (_ for _ in ()).throw(OSError("injected cleanup failure"))
    client = wmi.WmiClient("illustrative-host", read_control=ReadControl(0.1))
    monkeypatch.setattr(client, "_build_backend", lambda mode: provider)
    with pytest.raises(ClientCleanupError):
        client.query("query")
    assert client.last_query_result.state == "failed"


def test_host_lease_separates_full_sessions_and_removes_idle_registry_entries():
    first_inside, second_waiting = Event(), Event()
    order = []

    def first():
        lease = WmiHostLease("same-host.")
        lease.acquire(None)
        try:
            first_inside.set()
            assert second_waiting.wait(2)
            time.sleep(0.05)
            assert order == []
            order.append("first-cleaned-up")
        finally:
            lease.release()

    def second():
        assert first_inside.wait(2)
        second_waiting.set()
        lease = WmiHostLease("SAME-HOST")
        lease.acquire(None)
        try:
            assert order == ["first-cleaned-up"]
            order.append("second-connected")
        finally:
            lease.release()

    with ThreadPoolExecutor(max_workers=2) as workers:
        first_result = workers.submit(first)
        second_result = workers.submit(second)
        first_result.result(timeout=3)
        second_result.result(timeout=3)
    assert order == ["first-cleaned-up", "second-connected"]
    assert "same-host" not in wmi_session._HOSTS


def test_stopped_lease_waiter_does_not_enter_the_other_clients_session():
    owner = WmiHostLease("same-host")
    owner.acquire(None)

    def wait():
        waiter = WmiHostLease("same-host")
        with ReadControl(0.08).operation("waiting read", lambda: None) as operation:
            with pytest.raises(ReadStoppedError):
                waiter.acquire(operation)
        return waiter

    try:
        with ThreadPoolExecutor(max_workers=1) as workers:
            with pytest.raises(ReadStoppedError):
                workers.submit(wait).result(timeout=2)
        assert owner._state is not None
        assert owner._state.owner_thread == get_ident()
    finally:
        owner.release()
    assert "same-host" not in wmi_session._HOSTS


def test_two_hosts_can_hold_independent_sessions():
    first, second = WmiHostLease("first-host"), WmiHostLease("second-host")
    first.acquire(None)
    try:
        second.acquire(None)
        second.release()
    finally:
        first.release()


def test_second_client_on_same_thread_fails_instead_of_deadlocking():
    first, second = WmiHostLease("same-host"), WmiHostLease("same-host")
    first.acquire(None)
    try:
        with pytest.raises(RuntimeError, match="Close the first WMI read"):
            second.acquire(None)
    finally:
        first.release()
    assert "same-host" not in wmi_session._HOSTS


def test_monitor_cannot_cancel_later_work_on_reused_owner_thread():
    interruptions = []
    with ReadControl(0.2).operation("healthy read", lambda: interruptions.append(True)):
        pass
    time.sleep(0.25)
    assert interruptions == []


@pytest.mark.parametrize("seconds", [0, -1, float("inf"), float("nan"), True])
def test_invalid_budgets_are_rejected(seconds):
    with pytest.raises(ValueError):
        ReadControl(seconds)


def test_rejected_identity_is_never_resubmitted_and_secret_is_redacted(
    monkeypatch, caplog
):
    calls = []

    class Rejection(Exception):
        def get_error_code(self):
            return 0xC000006D

    class Provider:
        def connect(self):
            calls.append(True)
            raise Rejection("the supplied test-only-password was rejected")

        def close(self):
            pass

    client = wmi.WmiClient(
        "host", wmi.WmiAuth(username="identity", password="test-only-password")
    )
    monkeypatch.setattr(client, "_build_backend", lambda mode: Provider())
    assert client.query("query") == []
    assert client.query("query") == []
    assert calls == [True]
    assert "test-only-password" not in caplog.text


def test_native_monitor_does_not_initialize_its_own_com_apartment(monkeypatch):
    from openhound_collector_common.clients import operations

    calls = []
    interrupted = Event()
    native = wmi._PyWin32Backend("host")
    native._native_thread_id = 123

    def cancel(thread_id):
        calls.append(thread_id)
        interrupted.set()

    monkeypatch.setattr(wmi, "cancel_windows_call", cancel)
    with pytest.raises(ReadStoppedError):
        with operations.ReadControl(0.05).operation("native read", native.interrupt):
            # Wait for the behavior being tested. A short sleep could end before
            # the monitor received CPU time on a busy validation machine.
            assert interrupted.wait(5)
    assert calls and set(calls) == {123}


def test_complete_object_uses_lease_and_always_closes_the_raw_backend(monkeypatch):
    backend = wmi._ImpacketBackend(
        "host",
        domain="domain",
        username="identity",
        password="",
        lmhash="",
        nthash="",
        do_kerberos=False,
        kdc_host=None,
    )
    events = []
    obj = SimpleNamespace(
        getProperties=lambda: {"Permissions": {"value": [1, 2]}},
        RemRelease=lambda: events.append("object-released"),
    )
    monkeypatch.setattr(
        backend,
        "_services_for",
        lambda ns: SimpleNamespace(GetObject=lambda path: (obj, None)),
    )
    monkeypatch.setattr(backend, "close", lambda: events.append("session-closed"))
    assert backend.read_instance("namespace", "object") == {"Permissions": [1, 2]}
    assert events == ["object-released", "session-closed"]


def test_real_provider_maps_do_not_mix_two_concurrent_clients_credentials(monkeypatch):
    first_reading, second_started = Event(), Event()

    def before_row():
        first_reading.set()
        assert second_started.wait(2)
        time.sleep(0.05)

    install_provider(monkeypatch, before_row)

    def read(identity):
        if identity == "second-invented-identity":
            assert first_reading.wait(2)
            second_started.set()
        client = wmi.WmiClient(
            "same-host",
            wmi.WmiAuth(username=identity, password="inert-test-password"),
            read_control=ReadControl(2),
        )
        try:
            rows = client.query("illustrative-query")
            assert client.last_query_result.state == "completed"
            return rows
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(read, "first-invented-identity")
        second = workers.submit(read, "second-invented-identity")
        assert first.result(timeout=3) == [{"identity": "first-invented-identity"}]
        assert second.result(timeout=3) == [{"identity": "second-invented-identity"}]
    assert "same-host" not in wmi_session._HOSTS


def test_client_rejects_overlap_without_closing_the_active_read(monkeypatch):
    provider = ControlledBackend()
    client = wmi.WmiClient("illustrative-host", read_control=ReadControl(0.3))
    monkeypatch.setattr(client, "_build_backend", lambda mode: provider)
    with client._reading():
        client._backend = provider
        assert client.query("overlapping query") == []
        assert not provider.closed
    client.close()


def test_raw_provider_cannot_release_a_different_threads_lease():
    lease = WmiHostLease("same-host")
    lease.acquire(None)
    try:
        with ThreadPoolExecutor(max_workers=1) as workers:
            with pytest.raises(RuntimeError, match="owning thread"):
                workers.submit(lease.release).result(timeout=2)
        assert lease._state is not None
    finally:
        lease.release()


@pytest.mark.parametrize("expired_target", [False, True])
def test_cleanup_still_runs_after_a_stop_or_expired_target(expired_target):
    stop = Event()
    control = ReadControl(
        1,
        deadline=Deadline(time.monotonic() - 1) if expired_target else None,
        stop_event=stop,
    )
    client = wmi.WmiClient("host", read_control=control)
    provider = ControlledBackend()
    client._backend = provider
    stop.set()
    client.close()
    assert provider.closed and client._backend is None
