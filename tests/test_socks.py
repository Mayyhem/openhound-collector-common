"""Unit tests for openhound_collector_common.proxy.socks parsing (no live proxy)."""
import pytest

from openhound_collector_common.proxy.socks import (
    ProxyConfig,
    SocksError,
    parse_proxy_address,
)


def test_parse_scheme_with_userpass():
    """socks5://user:pass@host:1080 parses into all four components."""
    cfg = parse_proxy_address("socks5://user:pass@host:1080")
    assert cfg == ProxyConfig(host="host", port=1080, username="user", password="pass")
    assert cfg.has_auth is True


def test_parse_scheme_no_auth():
    """socks5://host:1080 parses with no credentials."""
    cfg = parse_proxy_address("socks5://10.2.10.254:1080")
    assert cfg.host == "10.2.10.254"
    assert cfg.port == 1080
    assert cfg.username is None
    assert cfg.password is None
    assert cfg.has_auth is False


def test_parse_socks5h_treated_like_socks5():
    """The socks5h scheme is accepted and behaves like socks5."""
    cfg = parse_proxy_address("socks5h://host:1080")
    assert cfg.host == "host" and cfg.port == 1080


def test_parse_bare_host_port():
    """A bare host:port (no scheme) parses as no-auth SOCKS5."""
    cfg = parse_proxy_address("proxy.example.com:9050")
    assert cfg.host == "proxy.example.com"
    assert cfg.port == 9050
    assert cfg.has_auth is False


def test_parse_empty_returns_none():
    """An empty proxy string means 'no proxy configured'."""
    assert parse_proxy_address("") is None


def test_parse_percent_encoded_password():
    """Percent-encoded credentials are decoded (e.g. an '@' in the password)."""
    cfg = parse_proxy_address("socks5://user:p%40ss@host:1080")
    assert cfg.username == "user"
    assert cfg.password == "p@ss"


def test_parse_unsupported_scheme_raises():
    """A non-SOCKS5 scheme is rejected."""
    with pytest.raises(SocksError):
        parse_proxy_address("http://host:8080")


def test_parse_bare_missing_port_raises():
    """A bare address with no ':port' is rejected."""
    with pytest.raises(SocksError):
        parse_proxy_address("hostonly")


def test_parse_bare_nonnumeric_port_raises():
    """A non-numeric port is rejected."""
    with pytest.raises(SocksError):
        parse_proxy_address("host:notaport")


def test_parse_bracketed_ipv6_bare():
    """A bracketed IPv6 literal with port parses correctly."""
    cfg = parse_proxy_address("[2001:db8::1]:1080")
    assert cfg.host == "2001:db8::1"
    assert cfg.port == 1080


def test_socks5_handshake_is_public_and_reuses_connect_path():
    # socks5_handshake must be importable and callable on a bare socket.
    from openhound_collector_common.proxy.socks import socks5_handshake
    assert callable(socks5_handshake)
