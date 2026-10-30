"""Exercise the real impacket transport against owned loopback-only peers."""

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Thread

import pytest
from impacket.krb5 import kerberosv5

from openhound_collector_common.clients.kerberos_io import kerberos_exchange
from openhound_collector_common.clients.operations import (
    ClientCleanupError,
    ReadControl,
    ReadStoppedError,
    current_read_operation,
)


class Peer:
    """Send an ordinary reply, stall or trickle a body; never contact a KDC."""

    def __init__(self, mode="reply", reply=b"fixture reply"):
        self.mode = mode
        self.reply = reply
        self.accepted = Event()
        self.released = Event()
        self.done = Event()
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.connection = None
        self.thread = Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        try:
            while not self.done.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                self.connection = connection
                with connection:
                    connection.settimeout(2)
                    self.accepted.set()
                    request = connection.recv(4096)
                    assert request
                    if self.mode == "silence":
                        assert connection.recv(1) == b""
                    elif self.mode == "trickle":
                        connection.sendall(struct.pack("!i", 100))
                        while not self.done.wait(0.02):
                            connection.sendall(b"x")
                    elif self.mode == "short-prefix":
                        connection.sendall(b"\x00")
                        assert connection.recv(1) == b""
                    else:
                        connection.sendall(
                            struct.pack("!i", len(self.reply)) + self.reply
                        )
                        assert connection.recv(1) == b""
                    self.released.set()
                return
        except OSError:
            self.released.set()  # Expected when a stopped exchange closes its end.
        except BaseException as error:
            self.errors.append(error)

    def close(self):
        self.done.set()
        self.listener.close()
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
        self.thread.join(3)
        assert not self.thread.is_alive()
        assert not self.errors


def request(peer):
    return kerberosv5.sendReceive(
        b"local test request", "unused.invalid", "127.0.0.1", peer.port
    )


@pytest.mark.parametrize("mode", ["silence", "trickle"])
def test_elapsed_deadline_closes_a_real_owned_kerberos_connection(mode):
    peer = Peer(mode)
    original = kerberosv5.socket
    started = time.monotonic()
    try:
        with pytest.raises(ReadStoppedError):
            with kerberos_exchange(ReadControl(0.15)):
                request(peer)
        assert time.monotonic() - started < 2
        assert peer.accepted.is_set() and peer.released.wait(2)
        assert kerberosv5.socket is original
        assert current_read_operation() is None
    finally:
        peer.close()


def test_success_and_provider_parse_failure_both_release_their_connections():
    for mode in ("reply", "short-prefix"):
        peer = Peer(mode)
        try:
            if mode == "reply":
                with kerberos_exchange(ReadControl(2)):
                    assert request(peer) == peer.reply
            else:
                with pytest.raises(struct.error):
                    with kerberos_exchange(ReadControl(2)):
                        request(peer)
            assert peer.released.wait(2)
        finally:
            peer.close()


def test_run_stop_wakes_an_active_kdc_read_without_waiting_for_its_budget():
    peer = Peer("silence")
    stopped = Event()

    def stop_after_connect():
        assert peer.accepted.wait(2)
        stopped.set()

    stopper = Thread(target=stop_after_connect)
    stopper.start()
    try:
        with pytest.raises(ReadStoppedError):
            with kerberos_exchange(ReadControl(20, stop_event=stopped)):
                request(peer)
        assert peer.released.wait(2)
    finally:
        stopper.join(3)
        peer.close()


def test_concurrent_exchanges_keep_separate_deadlines_and_nested_scopes():
    slow, fast = Peer("silence"), Peer(reply=b"other identity's reply")
    uncontrolled = Peer(reply=b"unchanged default")
    original = kerberosv5.socket

    def stalled():
        with pytest.raises(ReadStoppedError):
            with kerberos_exchange(ReadControl(0.2)):
                request(slow)

    def succeeds():
        assert slow.accepted.wait(2)
        with kerberos_exchange(ReadControl(2)):
            owner = current_read_operation()
            with kerberos_exchange():
                assert current_read_operation() is owner
                result = request(fast)
        # A different, uncontrolled call can run while the module adapter is
        # installed for the stalled thread. It must not borrow that deadline.
        assert current_read_operation() is None
        assert request(uncontrolled) == uncontrolled.reply
        return result

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(stalled)
            second = workers.submit(succeeds)
            first.result(3)
            assert second.result(3) == fast.reply
        assert kerberosv5.socket is original
        assert current_read_operation() is None
    finally:
        slow.close()
        fast.close()
        uncontrolled.close()


def test_default_policy_leaves_the_provider_socket_reference_unchanged():
    original = kerberosv5.socket
    with kerberos_exchange():
        assert kerberosv5.socket is original is socket
    assert current_read_operation() is None


def test_failed_parent_read_restores_the_calling_threads_previous_scope():
    outer = ReadControl(2).operation("outer fixture", lambda: None)
    with outer:
        with pytest.raises(ValueError):
            with ReadControl(1).operation("inner fixture", lambda: None):
                raise ValueError("illustrative failure")
        assert current_read_operation() is outer
    assert current_read_operation() is None


def test_fatal_cleanup_is_not_relabelled_as_a_normal_stop():
    with pytest.raises(ClientCleanupError, match="original cleanup failure"):
        with kerberos_exchange(ReadControl(0.01)):
            time.sleep(0.02)
            raise ClientCleanupError("original cleanup failure")


def test_owned_socket_cleanup_failure_fails_and_restores_the_provider(monkeypatch):
    class BrokenSocket:
        def settimeout(self, timeout):
            pass

        def shutdown(self, direction):
            raise OSError("Not connected")

        def close(self):
            raise OSError("Illustrative close failure")

    monkeypatch.setattr(socket, "socket", lambda *args: BrokenSocket())
    original = kerberosv5.socket
    with pytest.raises(ClientCleanupError):
        with kerberos_exchange(ReadControl(1)):
            kerberosv5.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    assert kerberosv5.socket is original
    assert current_read_operation() is None
