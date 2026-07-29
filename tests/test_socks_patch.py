"""Tests for the process-wide SOCKS5 socket interception."""
import socket
import threading

import pytest

from openhound_collector_common.proxy import (
    ProxyConfig,
    active_proxy,
    socks_proxy_installed,
)


class _Socks5EchoStub:
    """Minimal no-auth SOCKS5 CONNECT server that echoes bytes after CONNECT.

    Speaks just enough of RFC 1928 to complete the handshake, then loops
    reading and echoing so a test can prove data flows through the tunnel.
    """

    def __init__(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.host, self.port = self._srv.getsockname()
        self.saw_domain = None  # the CONNECT target name, for socks5h assertions
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        conn, _ = self._srv.accept()
        with conn:
            # greeting: VER, NMETHODS, METHODS...
            ver, nmethods = conn.recv(2)
            conn.recv(nmethods)
            conn.sendall(bytes([0x05, 0x00]))  # no-auth selected
            # request: VER, CMD, RSV, ATYP, ADDR, PORT
            head = conn.recv(4)
            atyp = head[3]
            if atyp == 0x03:  # DOMAINNAME
                length = conn.recv(1)[0]
                self.saw_domain = conn.recv(length).decode()
            elif atyp == 0x01:
                conn.recv(4)
            else:
                conn.recv(16)
            conn.recv(2)  # port
            # reply: success, bound 0.0.0.0:0
            conn.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)

    def close(self):
        self._srv.close()


@pytest.fixture
def stub():
    s = _Socks5EchoStub()
    yield s
    s.close()


def test_context_manager_installs_and_restores(stub):
    orig_socket = socket.socket
    orig_create = socket.create_connection
    orig_getaddr = socket.getaddrinfo
    proxy = ProxyConfig(host=stub.host, port=stub.port)
    with socks_proxy_installed(proxy):
        assert active_proxy() == proxy
        assert socket.socket is not orig_socket  # hook installed
    # everything restored on exit
    assert active_proxy() is None
    assert socket.socket is orig_socket
    assert socket.create_connection is orig_create
    assert socket.getaddrinfo is orig_getaddr


def test_none_proxy_is_passthrough():
    orig_socket = socket.socket
    with socks_proxy_installed(None):
        assert active_proxy() is None
        assert socket.socket is orig_socket  # nothing installed


def test_traffic_flows_through_proxy_by_name(stub):
    # Connecting to an unresolvable internal name must succeed via the proxy
    # (socks5h): the name is sent to the proxy, never resolved locally.
    proxy = ProxyConfig(host=stub.host, port=stub.port)
    with socks_proxy_installed(proxy):
        sock = socket.create_connection(("server01.internal.invalid", 445), timeout=5)
        try:
            sock.sendall(b"ping")
            assert sock.recv(4) == b"ping"
        finally:
            sock.close()
    assert stub.saw_domain == "server01.internal.invalid"


def test_loopback_is_not_proxied(stub):
    # A loopback target must bypass the proxy entirely (guard against
    # re-proxying local/dlt traffic and against proxy self-recursion).
    echo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)
    port = echo.getsockname()[1]
    accepted = {}

    def _accept():
        c, _ = echo.accept()
        accepted["peer"] = True
        c.close()

    threading.Thread(target=_accept, daemon=True).start()
    proxy = ProxyConfig(host=stub.host, port=stub.port)
    with socks_proxy_installed(proxy):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.close()
    echo.close()
    assert accepted.get("peer") is True
    assert stub.saw_domain is None  # proxy never saw the loopback connect
