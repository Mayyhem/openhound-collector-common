"""Interrupt actual owned sockets, including slow reads, without killing workers."""

import socket
import time
from types import SimpleNamespace
from threading import Event

import pytest

from openhound_collector_common.clients import mssql
from openhound_collector_common.clients.operations import (
    ClientCleanupError,
    ReadControl,
    ReadStoppedError,
)


class WaitingTds:
    def __init__(self, reader, *, cleanup_fails=False):
        self.socket = reader
        self.closed = False
        self.cleanup_fails = cleanup_fails

    def connect(self, **kwargs):
        pass

    def RunSQLQuery(self, database, sql):
        self.socket.recv(1)
        return [{"late": "must not be accepted"}]

    def disconnect(self):
        self.socket.close()
        self.closed = True
        if self.cleanup_fails:
            raise OSError("Illustrative cleanup failure")


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_query_interrupts_only_its_socket_and_waits_for_disconnect(cleanup_fails):
    reader, peer = socket.socketpair()
    reader.settimeout(3)
    unrelated, unrelated_peer = socket.socketpair()
    backend = WaitingTds(reader, cleanup_fails=cleanup_fails)
    client = mssql.MssqlConnection(read_control=ReadControl(0.05))
    client._client = backend
    try:
        started = time.monotonic()
        expected = ClientCleanupError if cleanup_fails else ReadStoppedError
        with pytest.raises(expected):
            client.query("illustrative read")
        assert backend.closed and reader.fileno() == -1
        assert time.monotonic() - started < 2
        unrelated_peer.sendall(b"safe")
        assert unrelated.recv(4) == b"safe"
        with pytest.raises(ReadStoppedError):
            client.query("must not reuse a stopped connection")
    finally:
        reader.close()
        peer.close()
        unrelated.close()
        unrelated_peer.close()


def test_complete_query_cannot_cancel_the_next_user_of_the_connection():
    reader, peer = socket.socketpair()

    class ReadyTds(WaitingTds):
        def RunSQLQuery(self, database, sql):
            return [{"text": self.socket.recv(1).decode()}]

    # Allow ordinary loaded-Windows scheduling to finish an immediately ready
    # read; the later wait still crosses the old deadline and detects a late cancel.
    client = mssql.MssqlConnection(read_control=ReadControl(0.25))
    client._client = ReadyTds(reader)
    try:
        peer.sendall(b"a")
        assert client.query("first") == [{"text": "a"}]
        time.sleep(0.3)
        peer.sendall(b"b")
        assert client.query("second") == [{"text": "b"}]
    finally:
        client.close()
        peer.close()


def test_login_stop_cannot_try_a_second_connection_strategy(monkeypatch):
    reader, peer = socket.socketpair()
    backend = WaitingTds(reader)
    attempts = []

    def build(*args):
        attempts.append(args)
        return backend

    client = mssql.MssqlConnection(read_control=ReadControl(0.05))
    strategies = [
        SimpleNamespace(name=name, server_name="host", remote_name="host")
        for name in ("first", "second")
    ]
    monkeypatch.setattr(mssql, "_Tds", build)
    monkeypatch.setattr(client, "_build_strategies", lambda *args, **kwargs: strategies)
    monkeypatch.setattr(client, "_login", lambda *args: reader.recv(1) == b"")
    try:
        with pytest.raises(ReadStoppedError):
            client.connect(
                "host:1433",
                mssql.Auth(username="illustrative", password="illustrative"),
            )
        assert len(attempts) == 1
        assert backend.closed
    finally:
        reader.close()
        peer.close()


def test_linked_query_override_is_enforced_on_the_actual_read():
    reader, peer = socket.socketpair()
    client = mssql.MssqlConnection(read_control=ReadControl(30))
    client._client = WaitingTds(reader)
    try:
        with pytest.raises(ReadStoppedError):
            client.query("illustrative linked batch", timeout_seconds=0.05)
        assert reader.fileno() == -1
    finally:
        reader.close()
        peer.close()


def test_epa_stop_cannot_continue_the_manipulated_binding_probes(monkeypatch):
    reader, peer = socket.socketpair()
    backend = WaitingTds(reader)
    attempts = []
    backend.login_epa = lambda **kwargs: reader.recv(1) == b""

    def build(*args):
        attempts.append(args)
        return backend

    monkeypatch.setattr(mssql, "_Tds", build)
    try:
        with pytest.raises(ReadStoppedError):
            mssql.detect_epa(
                "host:1433",
                mssql.Auth(username="illustrative", password="illustrative"),
                read_control=ReadControl(0.05),
            )
        assert len(attempts) == 1
        assert backend.closed
    finally:
        reader.close()
        peer.close()


def test_cancelled_connection_cannot_begin_another_network_attempt(monkeypatch):
    stopped = Event()
    stopped.set()
    client = mssql.MssqlConnection(read_control=ReadControl(1, stop_event=stopped))

    def unexpected(*args):
        pytest.fail("A stopped connection must not create a TDS client")

    monkeypatch.setattr(mssql, "_Tds", unexpected)
    with pytest.raises(ReadStoppedError):
        client.connect(
            "illustrative:1433", mssql.Auth(username="example", password="example")
        )


def test_failed_socket_creation_is_not_a_cleanup_failure(monkeypatch):
    class NoSocket:
        socket = 0  # impacket's state before a socket has been opened.

        def connect(self, **kwargs):
            raise OSError("Illustrative refused connection")

        def disconnect(self):
            pytest.fail("There is no opened socket to disconnect")

    client = mssql.MssqlConnection(read_control=ReadControl(1))
    strategy = SimpleNamespace(name="first", server_name="host", remote_name="host")
    monkeypatch.setattr(mssql, "_Tds", lambda *args: NoSocket())
    monkeypatch.setattr(client, "_build_strategies", lambda *args, **kwargs: [strategy])
    with pytest.raises(OSError, match="refused"):
        client.connect(
            "illustrative:1433", mssql.Auth(username="example", password="example")
        )
