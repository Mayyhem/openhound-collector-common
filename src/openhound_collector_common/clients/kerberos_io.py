"""Bound only the Python sockets opened by an opted-in Kerberos exchange.

Impacket 0.13.1 owns the Kerberos protocol and cryptography, but its sendReceive
opens an unbounded socket and has no transport argument. Its module-local socket
reference is the narrow integration boundary here. The standard-library socket
module is untouched. A scoped adapter delegates uncontrolled calls unchanged;
each controlled thread owns its own sockets and deadline.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..discovery.network import SocketAddressInfo

from impacket.krb5 import kerberosv5

from ..logging import get_logger
from ..collection.errors import FatalCollectionError
from .operations import (
    ClientCleanupError,
    ReadControl,
    ReadOperation,
    ReadStoppedError,
    current_read_operation,
)

logger = get_logger(__name__)
_INSTALL_LOCK = Lock()
_ACTIVE_COUNT = 0
_PREVIOUS_SOCKET_MODULE: ModuleType | None = None
_CURRENT_IO: ContextVar[_OwnedKerberosIO | None] = ContextVar(
    "openhound_kerberos_io", default=None
)


class _OwnedKerberosIO:
    """Keep provider-created sockets until their owning exchange releases them."""

    def __init__(self) -> None:
        self.operation: ReadOperation | None = None
        self._guard = Lock()
        self._sockets: list[socket.socket] = []
        self._cleanup_error: OSError | None = None

    def open_socket(self, family: int, kind: int, protocol: int) -> socket.socket:
        assert self.operation is not None
        with self._guard:
            self.operation.check()
            connection = socket.socket(family, kind, protocol)
            # Register before setting options or returning the socket: even an
            # option/connect failure must leave it available to owned cleanup.
            self._sockets.append(connection)
            connection.settimeout(self.operation.remaining())
            return connection

    def close_sockets(self) -> None:
        """Wake the owned KDC receive/connect and close every created socket."""
        with self._guard:
            for connection in self._sockets:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    # Unconnected or already closed sockets need no shutdown.
                    logger.debug(
                        "Kerberos socket was unconnected or already closed during shutdown"
                    )
                try:
                    connection.close()
                except OSError as error:
                    logger.error("An owned Kerberos socket could not be closed")
                    if self._cleanup_error is None:
                        self._cleanup_error = error

    def finish(self) -> None:
        self.close_sockets()
        if self._cleanup_error is not None:
            logger.error("Kerberos exchange cleanup failed; the run must fail")
            raise ClientCleanupError(
                "Could not release an owned Kerberos socket"
            ) from self._cleanup_error

    def addresses(
        self, host: str, port: int, family: int, kind: int
    ) -> list[SocketAddressInfo]:
        """Resolve through selected DNS without an unbounded OS resolver call."""
        assert self.operation is not None
        self.operation.check()
        # Lazy import keeps generic read controls independent of discovery.
        from ..discovery.network import resolve_socket_addresses

        return resolve_socket_addresses(host, port, family, kind)


class _KerberosSocketAdapter:
    """The four socket names used by impacket 0.13.1's sendReceive function."""

    SOCK_STREAM = socket.SOCK_STREAM
    error = OSError

    @staticmethod
    def socket(family: int, kind: int, protocol: int = 0) -> socket.socket:
        selected = _CURRENT_IO.get()
        if selected is not None:
            return selected.open_socket(family, kind, protocol)
        return socket.socket(
            family, kind, protocol
        )  # Other callers keep their original policy.

    @staticmethod
    def getaddrinfo(
        host: str, port: int, family: int = 0, kind: int = 0
    ) -> list[SocketAddressInfo]:
        selected = _CURRENT_IO.get()
        if selected is not None:
            return selected.addresses(host, port, family, kind)
        return socket.getaddrinfo(host, port, family, kind)


_ADAPTER = _KerberosSocketAdapter()


@contextmanager
def _installed_adapter() -> Iterator[None]:
    """Keep one module adapter while any controlled exchange is active."""
    global _ACTIVE_COUNT, _PREVIOUS_SOCKET_MODULE
    with _INSTALL_LOCK:
        if _ACTIVE_COUNT == 0:
            if kerberosv5.socket is not socket:
                logger.error(
                    "Another integration already replaced the Kerberos socket boundary"
                )
                raise RuntimeError("Kerberos socket boundary is already customized")
            _PREVIOUS_SOCKET_MODULE = kerberosv5.socket
            kerberosv5.socket = _ADAPTER
        _ACTIVE_COUNT += 1
    try:
        yield
    finally:
        with _INSTALL_LOCK:
            _ACTIVE_COUNT -= 1
            if _ACTIVE_COUNT == 0:
                if kerberosv5.socket is not _ADAPTER:
                    logger.error(
                        "The Kerberos socket boundary changed during collection"
                    )
                    raise ClientCleanupError(
                        "Kerberos socket boundary could not be safely restored"
                    )
                kerberosv5.socket = _PREVIOUS_SOCKET_MODULE
                _PREVIOUS_SOCKET_MODULE = None


@contextmanager
def kerberos_exchange(control: ReadControl | None = None) -> Iterator[None]:
    """Use an explicit budget or inherit the calling SQL/LDAP/WMI read budget."""
    existing = _CURRENT_IO.get()
    if control is None and existing is not None:
        assert existing.operation is not None
        existing.operation.check()
        yield
        existing.operation.check()
        return  # A nested ticket helper belongs to the same owned exchange.
    parent = current_read_operation()
    if control is None and parent is not None:
        parent.check()
        control = ReadControl(parent.remaining(), parent.deadline, parent.stop_event)
    if control is None:
        yield
        return  # Existing consumers do not opt into controls implicitly.
    owned = _OwnedKerberosIO()
    operation = control.operation("Kerberos ticket exchange", owned.close_sockets)
    owned.operation = operation
    with _installed_adapter(), operation:
        token = _CURRENT_IO.set(owned)
        try:
            yield
            operation.check()
        except FatalCollectionError:
            logger.error("Kerberos exchange encountered a fatal cleanup failure")
            raise
        except Exception as error:
            if operation.is_stopped or isinstance(error, TimeoutError):
                logger.warning(
                    "Kerberos ticket exchange stopped; no authentication retry is allowed"
                )
                raise ReadStoppedError(
                    "Kerberos ticket exchange was stopped"
                ) from error
            raise  # Preserve actual provider/account failures.
        finally:
            _CURRENT_IO.reset(token)
            owned.finish()
