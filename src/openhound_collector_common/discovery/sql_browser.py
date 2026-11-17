"""Resolve a specific SQL instance using Microsoft's SQL Browser protocol.

The caller selects whether UDP is permitted and supplies its own graph policy.
ASCII instance names work on every server code page. A caller that knows the
shared client/server code page can supply its Python codec name for other names;
we never guess a remote Windows code page from the collector's operating system.
"""

from __future__ import annotations

import socket
import struct
from contextlib import nullcontext
from threading import Lock

from ..clients.operations import ReadControl, current_read_operation, socket_read
from ..logging import get_logger
from .network import resolve_socket_addresses

logger = get_logger(__name__)


def _instance_bytes(instance: str, encoding: str) -> bytes:
    """Encode the protocol's name field and enforce its 32-byte limit."""
    try:
        encoded = instance.encode(encoding)
    except (UnicodeError, LookupError) as error:
        logger.warning("SQL Browser instance name cannot use the selected code page")
        raise ValueError(
            "SQL Browser needs a known compatible code page for this name"
        ) from error
    if not encoded or len(encoded) > 32 or b"\x00" in encoded:
        logger.warning("SQL Browser instance name must contain 1..32 non-null bytes")
        raise ValueError("SQL Browser instance name must contain 1..32 non-null bytes")
    # Valid names need no extra log before the caller's resolution message.
    return encoded


def parse_browser_reply(reply: bytes, instance: str, *, encoding: str = "ascii") -> int:
    """Accept a complete reply for this instance with one valid TCP-port value.

    Only protocol keys, the TCP value, and the requested instance are interpreted.
    Unrelated values, such as a localized server name, need not be ASCII.
    """
    _instance_bytes(instance, encoding)
    if len(reply) < 3 or reply[0] != 0x05:
        logger.warning("SQL Browser returned an invalid response header")
        raise ValueError("SQL Browser response has an invalid header")
    size = struct.unpack_from("<H", reply, 1)[0]
    if size != len(reply) - 3 or size > 1024:
        logger.warning("SQL Browser returned an invalid response length")
        raise ValueError("SQL Browser response has an invalid length")
    try:
        if not reply.endswith(b";;"):
            raise ValueError("SQL Browser response is not terminated")
        parts = reply[3:-2].split(b";")
        if len(parts) % 2:
            raise ValueError("SQL Browser response has incomplete key/value pairs")
        fields: dict[bytes, bytes] = {}
        for name, value in zip(parts[::2], parts[1::2], strict=True):
            key = name.lower()
            if key in fields:
                raise ValueError("SQL Browser response repeats a key")
            # Each protocol field has one value; no earlier value is overwritten.
            fields[key] = value
        if (
            fields.get(b"instancename", b"").decode(encoding).casefold()
            != instance.casefold()
        ):
            raise ValueError("SQL Browser replied for a different instance")
        from .sql_server import sql_port

        port = sql_port(fields.get(b"tcp", b"").decode("ascii"))
    except (UnicodeError, ValueError) as error:
        logger.warning("SQL Browser response could not be used: %s", error)
        raise ValueError(f"Invalid SQL Browser response: {error}") from error
    logger.debug("SQL Browser resolved instance %s to TCP port %d", instance, port)
    return port


class SqlBrowserResolver:
    """Cache known instance ports for one run without importing a collector."""

    def __init__(self, *, encoding: str = "ascii") -> None:
        self.encoding = encoding
        self._ports: dict[tuple[str, str], int] = {}
        self._lock = Lock()

    def resolve(
        self, host: str, instance: str, *, timeout: float, proxied: bool = False
    ) -> int:
        """Read this instance's TCP port; fail instead of assuming port 1433."""
        if proxied:
            logger.warning(
                "SQL Browser requires UDP; supply a known port through SOCKS"
            )
            raise ValueError(
                "SQL Browser uses UDP; supply an explicit port through SOCKS"
            )
        if timeout <= 0:
            logger.error("SQL Browser timeout must be positive")
            raise ValueError("SQL Browser timeout must be positive")
        request_name = _instance_bytes(instance, self.encoding)
        key = (host.casefold(), instance.casefold())
        parent = current_read_operation()
        if parent is not None:
            parent.check()
        # No enclosing read means the socket's own timeout governs this call.
        with self._lock:
            port = self._ports.get(key)
            if port is not None:
                logger.debug("Using saved SQL Browser port for %s\\%s", host, instance)
                return port
            # Only the first successful answer for this host/instance is cached.
            logger.info("Resolving SQL instance %s on %s", instance, host)
            address = resolve_socket_addresses(
                host, 1434, socket.AF_INET, socket.SOCK_DGRAM
            )[0][4]
            if parent is not None:
                parent.check()
                timeout = min(timeout, parent.remaining())
            # Without a parent, the positive caller-supplied timeout is unchanged.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                controlled = (
                    socket_read(
                        ReadControl(timeout, parent.deadline, parent.stop_event),
                        "SQL Browser read",
                        connection,
                    )
                    if parent is not None
                    else nullcontext()
                )
                with controlled:
                    connection.settimeout(timeout)
                    connection.connect(address)
                    connection.send(b"\x04" + request_name + b"\x00")
                    reply = connection.recv(1028)
            port = parse_browser_reply(reply, instance, encoding=self.encoding)
            self._ports[key] = port
            return port
