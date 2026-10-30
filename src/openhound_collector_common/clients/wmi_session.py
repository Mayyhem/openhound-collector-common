"""Give one explicit WMI session exclusive use of a provider's hostname entry.

Impacket 0.13.1 stores credentials by hostname, outside individual connections.
The lease must therefore cover login, every result and cleanup. A login-only
lock would still let a later connection replace the first connection's identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, get_ident

from ..logging import get_logger
from .operations import ReadOperation

logger = get_logger(__name__)


@dataclass
class _HostState:
    lock: Lock = field(default_factory=Lock)
    users: int = 0
    owner_thread: int | None = None


_HOSTS: dict[str, _HostState] = {}
_HOSTS_GUARD = Lock()


class WmiHostLease:
    """Release this hostname only after its connection has finished cleanup."""

    def __init__(self, target: str) -> None:
        self.target = target.rstrip(".").casefold()
        self._state: _HostState | None = None

    def acquire(self, operation: ReadOperation | None) -> None:
        """Wait cooperatively; an expired waiting read never submits credentials."""
        if self._state is not None:
            self.check_owner()
            return  # This backend already owns the lease for its current read.
        with _HOSTS_GUARD:
            state = _HOSTS.setdefault(self.target, _HostState())
            state.users += 1
            reentered = state.owner_thread == get_ident()
        acquired = False
        try:
            if reentered:
                logger.error(
                    "Another WMI client on this thread still owns %s", self.target
                )
                raise RuntimeError(
                    "Close the first WMI read before opening another on the same host"
                )
            logger.debug(
                "Waiting for exclusive WMI provider ownership of %s", self.target
            )
            while not acquired:
                if operation is not None:
                    operation.check()
                # Existing callers without read controls keep waiting for their session.
                acquired = state.lock.acquire(timeout=0.05)
            with _HOSTS_GUARD:
                state.owner_thread = get_ident()
            self._state = state
            logger.debug("Acquired exclusive WMI provider ownership of %s", self.target)
        finally:
            if not acquired:
                with _HOSTS_GUARD:
                    state.users -= 1
                    if state.users == 0:
                        del _HOSTS[self.target]
                    # A remaining owner/waiter still needs this registry entry.

    def release(self) -> None:
        """Remove idle registry entries so a large scan does not retain host locks."""
        state = self._state
        if state is None:
            return  # An unconnected or already closed backend has no lease.
        self.check_owner()
        with _HOSTS_GUARD:
            state.owner_thread = None
            state.lock.release()
            state.users -= 1
            if state.users == 0:
                del _HOSTS[self.target]
            # A waiting caller keeps the same lock until it acquires ownership.
        self._state = None
        logger.debug("Released exclusive WMI provider ownership of %s", self.target)

    def check_owner(self) -> None:
        """Provider calls and cleanup must stay on the thread that acquired it."""
        if self._state is not None and self._state.owner_thread != get_ident():
            logger.error("WMI session for %s belongs to another thread", self.target)
            raise RuntimeError("Use and close the WMI session on its owning thread")
