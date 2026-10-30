"""Bound a socket operation by elapsed time, including a slow trickle of bytes."""

from __future__ import annotations

import socket
import time
import math
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event, Lock, Timer

from ..logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class Deadline:
    """One elapsed-time budget shared by all attempts at an operation."""

    expires_at: float

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        """Start a positive elapsed-time budget using the monotonic clock."""
        if not math.isfinite(seconds) or seconds <= 0:
            logger.error("A connection deadline must be positive")
            raise ValueError("A connection deadline must be positive")
        return cls(time.monotonic() + seconds)

    def remaining(self) -> float:
        """Return the remaining seconds, or stop before another attempt starts."""
        seconds = self.expires_at - time.monotonic()
        if seconds <= 0:
            logger.warning("The connection deadline expired")
            raise TimeoutError("The connection deadline expired")
        return seconds

    @contextmanager
    def bound_socket(self, connection: socket.socket) -> Iterator[None]:
        """Interrupt only this socket when the deadline expires.

        A receive timeout restarts whenever data arrives. The timer shuts down
        this connection even when a slow peer keeps delivering individual bytes.
        Locking ensures a completed operation cannot have its reused socket
        closed by a late timer callback. No worker thread is forcibly terminated.
        """
        seconds = self.remaining()
        expired = Event()
        finished = Event()
        guard = Lock()

        def interrupt() -> None:
            with guard:
                if finished.is_set():
                    # Cancellation won the race; this socket belongs to its caller.
                    return
                expired.set()
                logger.warning("Closing a connection whose deadline expired")
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError as error:
                    logger.debug("Deadline shutdown found an already closed socket: %s", error)
                finally:
                    connection.close()

        timer = Timer(seconds, interrupt)
        timer.daemon = True
        timer.start()
        try:
            yield
        finally:
            with guard:
                finished.set()
                timer.cancel()
            if expired.is_set():
                logger.warning("The socket operation exceeded its connection deadline")
                raise TimeoutError("The connection deadline expired")
