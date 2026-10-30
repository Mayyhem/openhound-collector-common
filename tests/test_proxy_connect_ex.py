"""Check the DNS socket entry point through local SOCKS fixtures."""

from __future__ import annotations

import socket
import time
from threading import Event, Thread

import pytest

from openhound_collector_common.proxy import ProxyConfig, socks_proxy_installed
from openhound_collector_common.proxy.patch import _bypass
from test_socks_patch import _Socks5EchoStub


@pytest.mark.parametrize("original_timeout", [None, 0, 0.5])
def test_connect_ex_uses_proxy_and_preserves_the_requested_socket_mode(
    original_timeout,
):
    proxy = _Socks5EchoStub()
    try:
        with socks_proxy_installed(
            ProxyConfig(proxy.host, proxy.port), connect_timeout=1
        ):
            with socket.socket() as connection:
                connection.settimeout(original_timeout)
                assert connection.connect_ex(("only-at-proxy.invalid", 1433)) == 0
                assert connection.gettimeout() == original_timeout
                connection.settimeout(1)
                connection.sendall(b"ping")
                assert connection.recv(4) == b"ping"
        assert proxy.saw_domain == "only-at-proxy.invalid"
    finally:
        proxy.close()


@pytest.mark.parametrize("reject", [False, True])
def test_failed_or_stalled_proxy_returns_failure_without_a_direct_retry(reject):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    stop = Event()
    calls = []

    def serve():
        connection, _peer = listener.accept()
        with connection:
            calls.append(connection.recv(3))
            if reject:
                connection.sendall(b"\x05\xff")
            else:
                stop.wait(timeout=2)

    worker = Thread(target=serve, daemon=True)
    worker.start()
    try:
        with socks_proxy_installed(
            ProxyConfig(*listener.getsockname()), connect_timeout=0.15
        ):
            with socket.socket() as connection:
                connection.setblocking(False)
                started = time.monotonic()
                result = connection.connect_ex(
                    ("must-not-connect-directly.invalid", 1433)
                )
                assert result != 0
                assert time.monotonic() - started < 2
                if connection.fileno() != -1:
                    assert connection.gettimeout() == 0
        assert len(calls) == 1
    finally:
        stop.set()
        listener.close()
        worker.join(timeout=3)
        assert not worker.is_alive()


def test_only_the_proxys_actual_port_is_a_self_connection_exception():
    with socks_proxy_installed(ProxyConfig("10.10.10.100", 1080)):
        assert _bypass("10.10.10.100", 1080)
        assert not _bypass("10.10.10.100", 53)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_proxy_connection_limit_must_be_positive_and_finite(timeout):
    with pytest.raises(ValueError, match="finite and positive"):
        with socks_proxy_installed(
            ProxyConfig("127.0.0.1", 1080), connect_timeout=timeout
        ):
            pass
