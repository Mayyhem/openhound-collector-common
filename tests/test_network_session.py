"""Check chosen DNS, proxy routing, restoration, and failures with local fixtures."""

from __future__ import annotations

import ipaddress
import socket
import struct
from threading import Event, Thread

import dns.exception
import dns.message
import dns.rrset
import pytest

from openhound_collector_common.discovery.network import check_tcp_port, network_session
from openhound_collector_common.proxy.patch import active_proxy
from openhound_collector_common.clients.operations import (
    ReadControl,
    ReadStoppedError,
    ClientCleanupError,
)


def receive_exact(connection, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("The local fixture connection ended early")
        chunks.extend(chunk)
    return bytes(chunks)


class DnsProxy:
    """Answer TCP DNS and TCP probes inside a loopback-only SOCKS fixture.

    Destination addresses are recorded, never contacted. This makes a DNS leak
    or missed SOCKS handshake visible without reaching any external target.
    """

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()
        self.destinations = []
        self.errors = []
        self.stopped = Event()
        self.thread = Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with connection:
                    connection.settimeout(2)
                    version, count = receive_exact(connection, 2)
                    assert version == 5
                    receive_exact(connection, count)
                    connection.sendall(b"\x05\x00")
                    header = receive_exact(connection, 4)
                    if header[3] == 1:
                        host = str(ipaddress.ip_address(receive_exact(connection, 4)))
                    elif header[3] == 3:
                        host = receive_exact(
                            connection, receive_exact(connection, 1)[0]
                        ).decode("ascii")
                    else:
                        raise AssertionError(
                            f"Unexpected fixture address type {header[3]}"
                        )
                    port = struct.unpack("!H", receive_exact(connection, 2))[0]
                    self.destinations.append((host, port))
                    connection.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                    if port == 53:
                        size = struct.unpack("!H", receive_exact(connection, 2))[0]
                        query = dns.message.from_wire(receive_exact(connection, size))
                        response = dns.message.make_response(query)
                        response.answer.append(
                            dns.rrset.from_text(
                                query.question[0].name, 30, "IN", "A", "10.10.11.51"
                            )
                        )
                        connection.sendall(response.to_wire(prepend_length=True))
            except Exception as error:
                self.errors.append(error)

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive()
        assert not self.errors


@pytest.mark.parametrize("controlled", [False, True])
def test_actual_tcp_dns_and_reachability_use_the_same_proxy(controlled):
    proxy = DnsProxy()
    original = {
        name: getattr(socket, name)
        for name in (
            "socket",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyaddr",
            "getfqdn",
            "create_connection",
        )
    }
    try:
        options = {"read_control": ReadControl(1)} if controlled else {}
        with network_session(
            proxy_address=f"socks5://{proxy.address[0]}:{proxy.address[1]}",
            dns_server="10.10.10.100",
            timeout=1,
            **options,
        ):
            assert socket.gethostbyname("sql.mayyhem.com") == "10.10.11.51"
            check_tcp_port("10.10.11.51", 51433, timeout=1, **options)
        assert proxy.destinations == [("10.10.10.100", 53), ("10.10.11.51", 51433)]
        assert active_proxy() is None
        assert all(getattr(socket, name) is value for name, value in original.items())
    finally:
        proxy.close()


def test_explicit_dns_wins_over_domain_controller_and_failure_restores(monkeypatch):
    original = socket.getaddrinfo
    with pytest.raises(RuntimeError, match="deliberate"):
        with network_session(
            dns_server="10.10.10.100", domain_controller="10.10.11.51"
        ) as resolver:
            assert resolver.nameservers == ["10.10.10.100"]
            with pytest.raises(RuntimeError, match="already active"):
                with network_session():
                    pass
            raise RuntimeError("deliberate")
    assert socket.getaddrinfo is original
    with network_session(domain_controller="10.10.11.51") as resolver:
        assert resolver.nameservers == ["10.10.11.51"]


def test_selected_dns_failure_never_falls_back_to_system_dns(monkeypatch):
    import dns.resolver

    def fail(*args, **kwargs):
        raise dns.exception.Timeout()

    # If code tries local DNS after the selected service fails, this fake
    # would appear to succeed and the required gaierror assertion would fail.
    monkeypatch.setattr(dns.resolver.Resolver, "resolve_name", fail)
    with network_session(dns_server="10.10.10.100"):
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("must-not-use-local-dns.invalid", 1433)


def test_tcp_probe_stop_closes_only_its_owned_connection_and_tries_no_more_addresses(
    monkeypatch,
):
    from openhound_collector_common.discovery import network

    closed = Event()
    attempts = []

    class WaitingSocket:
        def settimeout(self, seconds):
            assert 0 < seconds <= 1

        def connect(self, address):
            attempts.append(address)
            assert closed.wait(2), "Owned cancellation did not release the probe"
            raise OSError("Probe was closed")

        def shutdown(self, direction):
            closed.set()

        def close(self):
            closed.set()

    monkeypatch.setattr(
        network,
        "resolve_socket_addresses",
        lambda *args: [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", port))
            for port in (10001, 10002)
        ],
    )
    monkeypatch.setattr(socket, "socket", lambda *args: WaitingSocket())
    with pytest.raises(ReadStoppedError):
        check_tcp_port("unused.invalid", 1433, timeout=1, read_control=ReadControl(0.1))
    assert attempts == [("127.0.0.1", 10001)]


def test_tcp_probe_cleanup_failure_is_fatal(monkeypatch):
    from openhound_collector_common.discovery import network

    class BrokenSocket:
        def settimeout(self, seconds):
            pass

        def connect(self, address):
            pass

        def close(self):
            raise OSError("Illustrative close failure")

    monkeypatch.setattr(
        network,
        "resolve_socket_addresses",
        lambda *args: [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1433))
        ],
    )
    monkeypatch.setattr(socket, "socket", lambda *args: BrokenSocket())
    with pytest.raises(ClientCleanupError):
        check_tcp_port("unused.invalid", 1433, timeout=1, read_control=ReadControl(1))
