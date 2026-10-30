"""A complete LDAP search shares one budget across bind, pages and owned cleanup."""

import socket
import time
from types import SimpleNamespace
from threading import Event, Thread

import pytest

from openhound_collector_common.clients.ad import AdClient, LdapAuth
from openhound_collector_common.clients.operations import (
    ClientCleanupError,
    ReadControl,
    ReadStoppedError,
)


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_stop_during_second_page_preserves_first_page_and_records_incomplete(
    cleanup_fails,
):
    reader, peer = socket.socketpair()
    # A test-only fallback avoids leaving a faulty cancellation implementation
    # blocked forever. The assertion below requires it to stop much earlier.
    reader.settimeout(3)
    stopped = Event()

    class Entry:
        entry_dn = "CN=complete"
        entry_attributes = ["name"]

        def __getitem__(self, name):
            return SimpleNamespace(raw_values=[b"complete"])

    class Connection:
        bound = True
        socket = reader

        def __init__(self):
            self.calls = 0
            self.unbound = False

        def search(self, **kwargs):
            self.calls += 1
            if self.calls == 2:
                # Request the stop after the complete first page was delivered;
                # machine scheduling must not expire a tiny budget before it.
                stopped.set()
                reader.recv(1)
            self.entries = [Entry()]
            self.result = {
                "description": "success",
                "controls": {
                    "1.2.840.113556.1.4.319": {"value": {"cookie": b"next-page"}},
                },
            }

        def unbind(self):
            reader.close()
            self.unbound = True
            if cleanup_fails:
                raise OSError("Illustrative cleanup failure")

    connection = Connection()
    client = AdClient("example.test", read_control=ReadControl(2, stop_event=stopped))
    client._conn = connection
    try:
        started = time.monotonic()
        rows = iter(client.paged_search("(objectClass=*)", ["name"]))
        assert next(rows)["name"] == "complete"
        with pytest.raises(ClientCleanupError if cleanup_fails else ReadStoppedError):
            next(rows)
        assert connection.calls == 2
        assert time.monotonic() - started < 2
        assert connection.unbound and reader.fileno() == -1
        assert client.last_query_result.state == "failed"
        assert client.last_query_result.row_count is None
        assert not client._can_use_native_fallback(ReadStoppedError("stopped"))
    finally:
        reader.close()
        peer.close()


def test_actual_ldap3_bind_to_a_silent_owned_peer_stops_and_releases_its_socket():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    accepted = []

    def peer():
        connection, address = listener.accept()
        accepted.append(connection)
        connection.settimeout(3)
        try:
            # Read frames without replying. The illustrative identity cannot
            # authenticate here; this peer only tests owned socket cleanup.
            while connection.recv(4096):
                pass
        except OSError:
            pass  # Local cancellation closes the peer's connection.
        finally:
            connection.close()

    thread = Thread(target=peer)
    thread.start()
    client = AdClient(
        "example.test",
        dc="127.0.0.1",
        port=listener.getsockname()[1],
        auth=LdapAuth(username="EXAMPLE\\illustrative", password="illustrative"),
        read_control=ReadControl(0.3),
    )
    try:
        started = time.monotonic()
        with pytest.raises(ReadStoppedError):
            list(client.paged_search("(objectClass=*)", ["name"]))
        assert time.monotonic() - started < 2
        assert client._conn is None and client._opening_conn is None
        assert client.last_query_result.state == "failed"
    finally:
        listener.close()
        for connection in accepted:
            connection.close()
        thread.join(5)
    assert not thread.is_alive()
