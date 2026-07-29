# New module (no SCCM equivalent). Ports the INTENT of the Go dialer
# MSSQLHound/internal/proxydialer/proxydialer.go:
#   - parse `socks5://[user:pass@]host:port` and bare `host:port`,
#   - return a connected socket to a target host/port through the SOCKS5 proxy.
# The Go version leaned on golang.org/x/net/proxy.SOCKS5; we implement the small
# slice of RFC 1928 (CONNECT) + RFC 1929 (username/password auth) we need with
# stdlib `socket` + `struct` only — no third-party dependency.
"""Pure-Python SOCKS5 dialer.

Two public pieces:

- :func:`parse_proxy_address` — parse a proxy string into a :class:`ProxyConfig`.
  Accepts ``socks5://[user:pass@]host:port``, ``socks5h://...`` (treated the
  same — see note), and bare ``host:port`` (no auth).
- :func:`connect_through_socks5` — open a TCP connection to the proxy and issue a
  SOCKS5 ``CONNECT`` to a target host/port, returning the connected socket (the
  tunnel) for the caller to use as if it were a direct connection.

Note on ``socks5`` vs ``socks5h``: the Go code accepts both. In SOCKS terms the
``h`` variant asks the *proxy* to resolve the destination hostname (vs the client
resolving first). This dialer always sends the destination as a hostname
(SOCKS5 address type ``DOMAINNAME``) when it isn't already a literal IP, so the
proxy does the DNS — i.e. it behaves like ``socks5h`` regardless, which is the
right default for tunneling into a network you can't resolve locally.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, unquote

logger = logging.getLogger(__name__)

# RFC 1928 / 1929 protocol constants.
_SOCKS_VERSION = 0x05
_AUTH_NONE = 0x00
_AUTH_USERPASS = 0x02
_AUTH_NO_ACCEPTABLE = 0xFF
_USERPASS_VERSION = 0x01
_CMD_CONNECT = 0x01
_RSV = 0x00
_ATYP_IPV4 = 0x01
_ATYP_DOMAINNAME = 0x03
_ATYP_IPV6 = 0x04
_REP_SUCCEEDED = 0x00

# Human-readable SOCKS5 reply codes (RFC 1928 §6) for clearer errors.
_REPLY_MESSAGES = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class SocksError(Exception):
    """Raised when proxy parsing or the SOCKS5 handshake fails."""


@dataclass(frozen=True)
class ProxyConfig:
    """A parsed SOCKS5 proxy endpoint plus optional username/password auth."""

    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def has_auth(self) -> bool:
        """True if a username was supplied (RFC 1929 user/pass auth applies)."""
        return self.username is not None


def parse_proxy_address(proxy_addr: str) -> Optional[ProxyConfig]:
    """Parse a proxy address string into a :class:`ProxyConfig`.

    Supported forms (mirroring the Go dialer):
      * ``""`` (empty)                       -> ``None`` (no proxy configured)
      * ``host:port``                        -> SOCKS5, no auth
      * ``socks5://host:port``               -> SOCKS5, no auth
      * ``socks5://user:pass@host:port``     -> SOCKS5 with user/pass auth
      * ``socks5h://...``                    -> same as ``socks5://`` (see module docstring)

    Raises :class:`SocksError` on an unsupported scheme, a missing port, or a
    non-numeric port.
    """
    if not proxy_addr:
        # Empty string => no proxy, matching Go's `New("")` -> (nil, nil).
        logger.debug("parse_proxy_address: empty address; no proxy configured")
        return None

    if "://" in proxy_addr:
        # Scheme form: let urlsplit pull apart credentials/host/port for us.
        parts = urlsplit(proxy_addr)
        if parts.scheme not in ("socks5", "socks5h"):
            # Only SOCKS5 is supported (the Go code rejects everything else too).
            raise SocksError(
                f"unsupported proxy scheme {parts.scheme!r} (only socks5/socks5h)"
            )
        host = parts.hostname
        port = parts.port
        # urlsplit percent-decodes nothing for us; decode creds so a literal
        # ':' or '@' encoded as %3A/%40 in a password survives intact.
        username = unquote(parts.username) if parts.username is not None else None
        password = unquote(parts.password) if parts.password is not None else None
    else:
        # Bare host:port form (no scheme, no auth) — split on the LAST colon so
        # bracketed IPv6 literals and ordinary host:port both work.
        host, port_str = _split_host_port(proxy_addr)
        username = None
        password = None
        try:
            port = int(port_str)
        except ValueError as err:
            raise SocksError(f"invalid proxy port {port_str!r}") from err

    if not host:
        raise SocksError(f"proxy address {proxy_addr!r} is missing a host")
    if port is None:
        raise SocksError(f"proxy address {proxy_addr!r} is missing a port")

    logger.debug(
        "parse_proxy_address: host=%s port=%s auth=%s",
        host, port, "yes" if username is not None else "no",
    )
    return ProxyConfig(host=host, port=int(port), username=username, password=password)


def _split_host_port(addr: str) -> tuple[str, str]:
    """Split a bare ``host:port`` (or ``[ipv6]:port``) into ``(host, port)``."""
    if addr.startswith("["):
        # Bracketed IPv6 literal: host is inside the brackets.
        close = addr.rfind("]")
        if close == -1 or close + 1 >= len(addr) or addr[close + 1] != ":":
            raise SocksError(f"malformed bracketed proxy address {addr!r}")
        return addr[1:close], addr[close + 2:]
    # Plain host:port — rsplit so we tolerate (rare) unbracketed forms gracefully.
    host, sep, port = addr.rpartition(":")
    if not sep:
        raise SocksError(f"proxy address {addr!r} is missing a ':port'")
    return host, port


def socks5_handshake(
    sock: socket.socket,
    proxy: ProxyConfig,
    dest_host: str,
    dest_port: int,
) -> None:
    """Run the SOCKS5 greeting/auth + CONNECT on an already-open socket.

    *sock* must already be connected to the proxy endpoint. On return it is a
    live tunnel to ``(dest_host, dest_port)``. Raises :class:`SocksError` on any
    protocol failure (the caller owns closing the socket).
    """
    _socks5_negotiate_auth(sock, proxy)
    _socks5_connect(sock, dest_host, dest_port)


def connect_through_socks5(
    proxy: ProxyConfig,
    dest_host: str,
    dest_port: int,
    *,
    timeout: float = 10.0,
) -> socket.socket:
    """Open a SOCKS5 tunnel through *proxy* to ``(dest_host, dest_port)``.

    Returns the connected socket (already past the SOCKS5 handshake), which the
    caller uses as a normal stream socket to the destination. On any protocol or
    connection failure the partially-opened socket is closed and a
    :class:`SocksError` is raised.
    """
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        socks5_handshake(sock, proxy, dest_host, dest_port)
    except Exception:
        # Never leak the socket if the handshake fails part-way through.
        sock.close()
        raise
    logger.debug(
        "connect_through_socks5: tunnel established via %s:%s -> %s:%s",
        proxy.host, proxy.port, dest_host, dest_port,
    )
    return sock


def _socks5_negotiate_auth(sock: socket.socket, proxy: ProxyConfig) -> None:
    """Run the SOCKS5 greeting + (optional) RFC 1929 user/pass sub-negotiation."""
    if proxy.has_auth:
        # Offer both no-auth and user/pass so the proxy can pick.
        methods = bytes([_AUTH_NONE, _AUTH_USERPASS])
    else:
        # Only no-auth on offer.
        methods = bytes([_AUTH_NONE])
    sock.sendall(bytes([_SOCKS_VERSION, len(methods)]) + methods)

    resp = _recv_exact(sock, 2)
    if resp[0] != _SOCKS_VERSION:
        raise SocksError(f"proxy returned non-SOCKS5 version {resp[0]:#x}")
    chosen = resp[1]
    if chosen == _AUTH_NONE:
        # Proxy accepted anonymous access — nothing more to do.
        logger.debug("_socks5_negotiate_auth: proxy selected no-auth")
        return
    if chosen == _AUTH_USERPASS:
        # Proxy requires user/pass: we must have credentials to satisfy it.
        if not proxy.has_auth:
            raise SocksError("proxy requires username/password but none provided")
        _socks5_userpass_auth(sock, proxy)
        return
    if chosen == _AUTH_NO_ACCEPTABLE:
        # 0xFF => proxy rejected every method we offered.
        raise SocksError("proxy rejected all offered auth methods")
    # Any other selection is a method we never offered / can't perform.
    raise SocksError(f"proxy selected unsupported auth method {chosen:#x}")


def _socks5_userpass_auth(sock: socket.socket, proxy: ProxyConfig) -> None:
    """Perform RFC 1929 username/password authentication."""
    user = (proxy.username or "").encode("utf-8")
    pw = (proxy.password or "").encode("utf-8")
    if len(user) > 255 or len(pw) > 255:
        # RFC 1929 length fields are a single byte each.
        raise SocksError("proxy username/password exceeds 255 bytes")
    sock.sendall(
        bytes([_USERPASS_VERSION, len(user)]) + user + bytes([len(pw)]) + pw
    )
    resp = _recv_exact(sock, 2)
    if resp[0] != _USERPASS_VERSION:
        raise SocksError(f"unexpected user/pass auth version {resp[0]:#x}")
    if resp[1] != 0x00:
        # Non-zero status => credentials rejected.
        raise SocksError("proxy rejected username/password")
    logger.debug("_socks5_userpass_auth: credentials accepted")


def _socks5_connect(sock: socket.socket, dest_host: str, dest_port: int) -> None:
    """Issue the SOCKS5 CONNECT request and parse the bind-address reply."""
    # Pick the narrowest address type: IPv4/IPv6 literal if dest_host parses as
    # one, else DOMAINNAME so the *proxy* resolves the name (socks5h behavior).
    try:
        ip = ipaddress.ip_address(dest_host)
    except ValueError:
        ip = None

    if ip is None:
        # Non-IP destination => send the name and let the proxy resolve it.
        # IDNA-encode non-ASCII hostnames; plain ASCII goes as-is.
        if _is_ascii(dest_host):
            host_bytes = dest_host.encode("ascii")
        else:
            host_bytes = dest_host.encode("idna")
        if len(host_bytes) > 255:
            raise SocksError(f"destination hostname too long: {dest_host!r}")
        addr_part = bytes([_ATYP_DOMAINNAME, len(host_bytes)]) + host_bytes
    elif ip.version == 4:
        addr_part = bytes([_ATYP_IPV4]) + ip.packed
    else:
        addr_part = bytes([_ATYP_IPV6]) + ip.packed

    request = bytes([_SOCKS_VERSION, _CMD_CONNECT, _RSV]) + addr_part + struct.pack("!H", dest_port)
    sock.sendall(request)

    # Reply header: VER, REP, RSV, ATYP.
    header = _recv_exact(sock, 4)
    if header[0] != _SOCKS_VERSION:
        raise SocksError(f"proxy reply has non-SOCKS5 version {header[0]:#x}")
    if header[1] != _REP_SUCCEEDED:
        # Map the reply code to a readable message.
        reason = _REPLY_MESSAGES.get(header[1], f"unknown error {header[1]:#x}")
        raise SocksError(f"SOCKS5 CONNECT failed: {reason}")

    # Drain the bound address that follows, sized by its ATYP, so the socket is
    # left positioned exactly at the start of the tunneled stream.
    atyp = header[3]
    if atyp == _ATYP_IPV4:
        _recv_exact(sock, 4)
    elif atyp == _ATYP_IPV6:
        _recv_exact(sock, 16)
    elif atyp == _ATYP_DOMAINNAME:
        # First byte is the domain length; read it, then that many bytes.
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length)
    else:
        raise SocksError(f"proxy reply has unknown address type {atyp:#x}")
    # Followed by a 2-byte bound port we don't need but must consume.
    _recv_exact(sock, 2)
    logger.debug("_socks5_connect: CONNECT to %s:%s succeeded", dest_host, dest_port)


def _is_ascii(text: str) -> bool:
    """Return True if *text* is pure ASCII (so it needs no IDNA encoding)."""
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly *count* bytes from *sock* or raise on early EOF."""
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            # Peer closed before sending everything we expected.
            raise SocksError("proxy closed the connection during handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
