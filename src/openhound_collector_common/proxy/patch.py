# New module (no SCCM equivalent). Installs a process-wide SOCKS5 interception
# so every stdlib-socket-based client (ldap3, impacket, requests/urllib3,
# dnspython-over-TCP, raw probes) tunnels through the proxy with no per-call
# changes. Ports the INTENT of the Go MSSQLHound proxydialer, generalized from
# "one TDS dial" to "all in-process TCP", because the SCCM collector speaks five
# protocols across four libraries.
"""Process-wide SOCKS5 socket interception for OpenHound collectors.

`install(proxy)` swaps three things on the stdlib ``socket`` module:

- ``socket.socket``          -> :class:`_ProxiedSocket` (a subclass whose
  ``connect`` runs the SOCKS5 handshake to the destination).
- ``socket.create_connection`` -> :func:`create_connection` (passes the raw
  hostname to the proxy — never resolves a target name locally).
- ``socket.getaddrinfo``     -> :func:`getaddrinfo` (a pass-through that returns
  the hostname unresolved, so libraries that pre-resolve — e.g. urllib3 — hand
  the name to ``connect`` for socks5h resolution instead of failing on an
  internal-only name).

Loopback targets and the proxy endpoint itself are never proxied (recursion /
local-traffic guard). `uninstall()` restores the originals; prefer the
:func:`socks_proxy_installed` context manager so restore is guaranteed.

This is install-once-per-process: the collect pipeline already assumes a single
run per process. Not reentrant.
"""
from __future__ import annotations

import ipaddress
import logging
import socket as _socket
from contextlib import contextmanager
from typing import Iterator, Optional

from .socks import ProxyConfig, socks5_handshake

logger = logging.getLogger(__name__)

# The originals, captured at import so repeated install/uninstall can't stack.
_ORIG_SOCKET = _socket.socket
_ORIG_CREATE_CONNECTION = _socket.create_connection
_ORIG_GETADDRINFO = _socket.getaddrinfo

_ACTIVE: Optional[ProxyConfig] = None


def active_proxy() -> Optional[ProxyConfig]:
    """Return the currently-installed proxy, or None when direct."""
    return _ACTIVE


def _is_local(host: str) -> bool:
    """True if *host* is loopback (never proxied) — guards recursion/local dlt."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # A name: treat only the literal localhost as local. Everything else is
        # a target that must go through the proxy (resolved at the proxy).
        return host == "localhost"


def _bypass(host: str) -> bool:
    """True if a connection to *host* must NOT be proxied."""
    if _ACTIVE is None:
        return True  # no proxy installed — never intercept
    if host == _ACTIVE.host:
        return True  # the proxy's own endpoint (recursion guard)
    if _is_local(host):
        logger.debug("_bypass: %s is local; connecting direct", host)
        return True
    return False


class _ProxiedSocket(_ORIG_SOCKET):  # type: ignore[misc,valid-type]
    """A socket whose ``connect`` tunnels through the active SOCKS5 proxy."""

    def connect(self, address):  # noqa: D401 - stdlib override
        host = address[0]
        port = address[1]
        if _bypass(host):
            return super().connect(address)
        proxy = _ACTIVE
        # Connect to the proxy with the *real* connect (super), then hand the
        # destination NAME to the proxy so it resolves (socks5h).
        logger.debug("_ProxiedSocket.connect: tunneling to %s:%s via %s:%s",
                     host, port, proxy.host, proxy.port)
        super().connect((proxy.host, proxy.port))
        socks5_handshake(self, proxy, host, port)


def create_connection(address, timeout=_socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None):
    """Proxy-aware replacement for ``socket.create_connection``.

    For proxied targets we build a :class:`_ProxiedSocket` and connect by name
    (no local getaddrinfo). For bypassed targets we defer to the original.
    """
    host = address[0]
    if _bypass(host):
        return _ORIG_CREATE_CONNECTION(address, timeout, source_address)
    sock = _ProxiedSocket(_socket.AF_INET, _socket.SOCK_STREAM)
    try:
        if timeout is not _socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        if source_address is not None:
            sock.bind(source_address)
        sock.connect(address)  # runs the SOCKS handshake
    except Exception:
        sock.close()  # never leak a half-open socket on failure
        raise
    return sock


def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Pass-through resolver used while a proxy is active.

    Returns the hostname UNresolved so callers that pre-resolve (urllib3) hand
    the name to ``connect`` for socks5h resolution. Loopback/bypassed hosts are
    resolved for real so local traffic is unaffected.
    """
    if _bypass(host):
        return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)
    logger.debug("getaddrinfo: deferring resolution of %s to the proxy", host)
    st = type or _socket.SOCK_STREAM
    return [(_socket.AF_INET, st, proto, "", (host, port or 0))]


def install(proxy: ProxyConfig) -> None:
    """Install the process-wide interception for *proxy*."""
    global _ACTIVE
    if _ACTIVE is not None:
        # Not reentrant — a second install would stack wrappers. Fail loud.
        logger.error("install: a proxy (%s:%s) is already active", _ACTIVE.host, _ACTIVE.port)
        raise RuntimeError("SOCKS proxy already installed; uninstall first")
    _ACTIVE = proxy
    # Replacing names in the stdlib socket module IS the mechanism here: every library in
    # the process (ldap3, requests, impacket) resolves socket.socket at call time, so
    # rebinding it is what makes their traffic tunnel without any of them cooperating.
    # mypy objects because socket.socket is a type and create_connection has a fixed
    # signature; both objections are correct and both are the point.
    _socket.socket = _ProxiedSocket  # type: ignore[misc]
    _socket.create_connection = create_connection  # type: ignore[assignment]
    _socket.getaddrinfo = getaddrinfo
    logger.info("SOCKS5 proxy installed: all TCP now tunnels via %s:%s", proxy.host, proxy.port)


def uninstall() -> None:
    """Restore the original socket functions."""
    global _ACTIVE
    _socket.socket = _ORIG_SOCKET  # type: ignore[misc]  # see install(): rebinding a type
    _socket.create_connection = _ORIG_CREATE_CONNECTION
    _socket.getaddrinfo = _ORIG_GETADDRINFO
    if _ACTIVE is not None:
        logger.info("SOCKS5 proxy uninstalled (was %s:%s)", _ACTIVE.host, _ACTIVE.port)
    _ACTIVE = None


@contextmanager
def socks_proxy_installed(proxy: Optional[ProxyConfig]) -> Iterator[None]:
    """Install *proxy* for the duration of the block, then restore.

    A falsey *proxy* is a pass-through no-op, so callers can wrap a run
    unconditionally: ``with socks_proxy_installed(maybe_proxy): ...``.
    """
    if not proxy:
        logger.debug("socks_proxy_installed: no proxy; running direct")
        yield
        return
    install(proxy)
    try:
        yield
    finally:
        uninstall()
