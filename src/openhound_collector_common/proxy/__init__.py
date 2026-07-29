# New module (no SCCM equivalent). Ports the INTENT of the Go SOCKS5 dialer in
# MSSQLHound/internal/proxydialer/proxydialer.go to pure-Python stdlib so the
# collector's `--proxy` flag can tunnel TDS/LDAP connections through SOCKS5.
"""Pure-Python SOCKS5 proxy dialer for OpenHound collectors."""

from .patch import (
    active_proxy,
    install,
    socks_proxy_installed,
    uninstall,
)
from .socks import (
    ProxyConfig,
    SocksError,
    connect_through_socks5,
    parse_proxy_address,
    socks5_handshake,
)

__all__ = [
    "ProxyConfig",
    "SocksError",
    "active_proxy",
    "connect_through_socks5",
    "install",
    "parse_proxy_address",
    "socks5_handshake",
    "socks_proxy_installed",
    "uninstall",
]
