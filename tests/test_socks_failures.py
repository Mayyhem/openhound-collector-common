"""Separate unavailable destinations from failed or malformed proxy negotiation."""

import errno
import socket

import pytest

from openhound_collector_common.proxy import (
    ProxyConfig,
    SocksError,
    connect_through_socks5,
    socks5_handshake,
    socks_proxy_installed,
)
from test_socks_patch import _Socks5EchoStub


class ReplySocket:
    """Supply exact peer bytes, including deliberate truncation, without a network."""

    def __init__(self, reply):
        self.reply = bytearray(reply)
        self.closed = False

    def recv(self, size):
        part = bytes(self.reply[:size])
        del self.reply[:size]
        return part

    def sendall(self, data):
        pass  # Only the peer's reply varies in these failure checks.

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    ("reply_code", "expected_errno", "reason"),
    [
        (3, errno.ENETUNREACH, "network unreachable"),
        (4, errno.EHOSTUNREACH, "host unreachable"),
        (5, errno.ECONNREFUSED, "connection refused"),
    ],
)
@pytest.mark.parametrize(
    "bound_address",
    [b"\x01" + b"\x00" * 4, b"\x04" + b"\x00" * 16, b"\x03\x03lab"],
)
def test_complete_destination_failures_have_normal_socket_errors(
    reply_code, expected_errno, reason, bound_address
):
    peer = ReplySocket(
        b"\x05\x00" + bytes([5, reply_code, 0]) + bound_address + b"\x00\x00"
    )
    with pytest.raises(OSError, match=reason) as failure:
        socks5_handshake(peer, ProxyConfig("proxy", 1080), "sql.lab", 1433)
    assert failure.value.errno == expected_errno
    assert not isinstance(failure.value, SocksError)
    assert "sql.lab:1433" in str(failure.value)
    assert not peer.reply
    if reply_code == 5:
        assert isinstance(failure.value, ConnectionRefusedError)


@pytest.mark.parametrize("reply_code", [1, 2, 6, 7, 8, 255])
def test_other_proxy_failures_are_not_reported_as_unavailable_destinations(reply_code):
    peer = ReplySocket(b"\x05\x00" + bytes([5, reply_code, 0, 1]) + b"\x00" * 6)
    with pytest.raises(SocksError) as failure:
        socks5_handshake(peer, ProxyConfig("proxy", 1080), "sql.lab", 1433)
    assert not isinstance(failure.value, OSError)


@pytest.mark.parametrize(
    "reply",
    [
        b"\x05\xff",  # Proxy rejected the offered authentication methods.
        b"\x05\x02\x01\x01",  # Proxy rejected username/password authentication.
        b"\x05\x00\x04\x05\x00\x01" + b"\x00" * 6,  # Wrong SOCKS version.
        b"\x05\x00\x05\x05\x01\x01" + b"\x00" * 6,  # Nonzero reserved field.
        b"\x05\x00\x05\x05\x00\x09",  # Unknown address type.
        b"\x05\x00\x05\x05\x00\x01\x00",  # Truncated bound address.
        b"\x05\x00\x05\x05\x00\x01" + b"\x00" * 5,  # Truncated port.
    ],
)
def test_authentication_and_malformed_replies_stay_distinct(reply):
    peer = ReplySocket(reply)
    with pytest.raises(SocksError) as failure:
        socks5_handshake(
            peer, ProxyConfig("proxy", 1080, "user", "secret"), "sql.lab", 1433
        )
    assert not isinstance(failure.value, OSError)


def test_direct_dialer_closes_its_socket_after_a_destination_refusal(monkeypatch):
    peer = ReplySocket(b"\x05\x00\x05\x05\x00\x01" + b"\x00" * 6)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: peer)
    with pytest.raises(ConnectionRefusedError):
        connect_through_socks5(ProxyConfig("proxy", 1080), "sql.lab", 1433)
    assert peer.closed


@pytest.mark.parametrize("reply_code", [3, 4, 5])
@pytest.mark.parametrize("entry_point", ["create_connection", "connect", "connect_ex"])
def test_socket_entry_points_preserve_the_destination_failure(reply_code, entry_point):
    expected_errno = {
        3: errno.ENETUNREACH,
        4: errno.EHOSTUNREACH,
        5: errno.ECONNREFUSED,
    }[reply_code]
    proxy = _Socks5EchoStub(reply_code=reply_code)
    try:
        with socks_proxy_installed(ProxyConfig(proxy.host, proxy.port)):
            if entry_point == "create_connection":
                with pytest.raises(OSError) as failure:
                    socket.create_connection(("only-at-proxy.invalid", 1433), timeout=2)
                assert failure.value.errno == expected_errno
            else:
                with socket.socket() as connection:
                    connection.settimeout(2)
                    if entry_point == "connect_ex":
                        assert (
                            connection.connect_ex(("only-at-proxy.invalid", 1433))
                            == expected_errno
                        )
                    else:
                        with pytest.raises(OSError) as failure:
                            connection.connect(("only-at-proxy.invalid", 1433))
                        assert failure.value.errno == expected_errno
        assert proxy.saw_domain == "only-at-proxy.invalid"
    finally:
        proxy.close()
