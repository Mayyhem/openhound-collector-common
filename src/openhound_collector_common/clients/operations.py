"""Request that a slow read stop, then wait for the caller's actual cleanup.

The read stays on its owning thread. The monitor may cancel a Windows call or
shut down an owned socket, but never kills a thread or announces it finished.
Some Windows operations return after the requested time; that overrun is logged.
"""

from __future__ import annotations

import math
import socket
import time
from collections.abc import Callable
from contextvars import ContextVar, Token
from contextlib import contextmanager
from collections.abc import Iterator
from dataclasses import dataclass
from threading import Event, Lock, Thread

from ..logging import get_logger
from ..collection.errors import FatalCollectionError
from .deadline import Deadline

logger = get_logger(__name__)
_CHECK_INTERVAL = 0.05
_CURRENT_OPERATION: ContextVar[ReadOperation | None] = ContextVar(
    "openhound_read_operation", default=None
)


def current_read_operation() -> ReadOperation | None:
    """Return this thread's innermost owned read, never another worker's budget."""
    return _CURRENT_OPERATION.get()


class ReadStoppedError(TimeoutError):
    """A read exceeded its budget or its owner requested cancellation."""


class ClientCleanupError(FatalCollectionError):
    """Client cleanup failed; the owning run must report a failure."""


@dataclass(frozen=True)
class ReadControl:
    """An optional read budget, tightened by the remaining target budget.

    Attributes:
        timeout_seconds: Positive finite time before requesting cancellation.
        deadline: Optional deadline already shared by this target's operations.
        stop_event: Optional request to stop this target or collection run.
    """

    timeout_seconds: float
    deadline: Deadline | None = None
    stop_event: Event | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (float, int))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            logger.error("The read timeout must be positive and finite")
            raise ValueError("The read timeout must be positive and finite")
        if self.deadline is not None and (
            not isinstance(self.deadline, Deadline)
            or not math.isfinite(self.deadline.expires_at)
        ):
            logger.error("The target deadline must be finite")
            raise ValueError("The target deadline must be finite")
        if self.stop_event is not None and not isinstance(self.stop_event, Event):
            logger.error("The read stop request must be a thread Event")
            raise ValueError("The read stop request must be a thread Event")
        # Valid configuration needs no per-read log message.

    def operation(
        self, label: str, interrupt: Callable[[], None], *, is_cleanup: bool = False
    ) -> ReadOperation:
        """Create one monitored read, including time waiting for a host lease."""
        seconds = self.timeout_seconds
        if is_cleanup:
            # An expired target or stop event must never prevent releasing its
            # resources. Monitor cleanup immediately, but always let it run.
            expires_at = time.monotonic() + seconds
            if self.deadline is not None:
                expires_at = min(expires_at, self.deadline.expires_at)
            return ReadOperation(
                label, Deadline(expires_at), self.stop_event, interrupt, is_cleanup=True
            )
        if self.deadline is not None:
            try:
                seconds = min(seconds, self.deadline.remaining())
            except TimeoutError as error:
                logger.warning(
                    "%s cannot start because its target budget expired", label
                )
                raise ReadStoppedError(f"{label} target budget expired") from error
        # Without a target budget, use the caller's complete read budget.
        return ReadOperation(label, Deadline.after(seconds), self.stop_event, interrupt)

    def check(self) -> None:
        """Refuse another request or row after this target or run has stopped."""
        if self.stop_event is not None and self.stop_event.is_set():
            logger.warning("The collection stop request prevents further target work")
            raise ReadStoppedError("Collection was stopped")
        if self.deadline is not None:
            try:
                self.deadline.remaining()
            except TimeoutError as error:
                logger.warning(
                    "The target budget expired; refusing further requests or rows"
                )
                raise ReadStoppedError("Target budget expired") from error
        # A healthy target check has no operational consequence.


class ReadOperation:
    """Keep the monitor active until the read and its cleanup have returned."""

    def __init__(
        self,
        label: str,
        deadline: Deadline,
        stop_event: Event | None,
        interrupt: Callable[[], None],
        *,
        is_cleanup: bool = False,
    ) -> None:
        self.label = label
        self.deadline = deadline
        self._stop_event = stop_event
        self._interrupt = interrupt
        self._is_cleanup = is_cleanup
        self._finished = Event()
        self._stopped = Event()
        self._guard = Lock()
        self._monitor = Thread(
            target=self._watch, name="openhound-read-stop", daemon=False
        )
        self._scope_token: Token[ReadOperation | None] | None = None

    @property
    def stop_event(self) -> Event | None:
        """Let a nested protocol operation share its owner's stop request."""
        return self._stop_event

    @property
    def is_stopped(self) -> bool:
        """Include elapsed time even if the monitor has not sampled it yet."""
        return (
            self._stopped.is_set()
            or time.monotonic() >= self.deadline.expires_at
            or (self._stop_event is not None and self._stop_event.is_set())
        )

    def check(self) -> None:
        """Prevent another request or row after the stop condition is reached."""
        if self.is_stopped:
            logger.warning(
                "%s was stopped; refusing further requests or rows", self.label
            )
            raise ReadStoppedError(f"{self.label} was stopped")
        # Healthy polling decisions have no operational consequence.

    def remaining(self) -> float:
        """Return this read's remaining time with a consistent stopped-read error."""
        self.check()
        try:
            return self.deadline.remaining()
        except TimeoutError as error:
            # Time can expire between the check and the clock read, especially
            # if Windows schedules another thread in that interval.
            logger.warning("%s ran out of time before its next operation", self.label)
            raise ReadStoppedError(f"{self.label} was stopped") from error

    def __enter__(self) -> ReadOperation:
        if not self._is_cleanup:
            self.check()
        # Cleanup must still run after an already requested stop.
        self._monitor.start()
        self._scope_token = _CURRENT_OPERATION.set(self)
        return self

    def _watch(self) -> None:
        while not self._finished.wait(_CHECK_INTERVAL):
            if not self.is_stopped:
                continue  # Ordinary timing polls are deliberately quiet.
            with self._guard:
                if self._finished.is_set():
                    return  # The operation won the race; never cancel its next user.
                if not self._stopped.is_set():
                    logger.warning(
                        "%s reached its stop condition; waiting for the provider and cleanup",
                        self.label,
                    )
                    self._stopped.set()
                try:
                    self._interrupt()
                except Exception as error:
                    logger.warning(
                        "%s cancellation request failed (%s); still waiting for cleanup",
                        self.label,
                        type(error).__name__,
                    )

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            with self._guard:
                self._finished.set()
            self._monitor.join()
            if self.is_stopped:
                overrun = max(0.0, time.monotonic() - self.deadline.expires_at)
                logger.warning(
                    "%s returned after stopping (timeout overrun %.3fs)",
                    self.label,
                    overrun,
                )
                if exc_type is None and not self._is_cleanup:
                    raise ReadStoppedError(f"{self.label} was stopped")
                # Preserve an existing failure, especially a cleanup failure.
        finally:
            if self._scope_token is not None:
                _CURRENT_OPERATION.reset(self._scope_token)
                self._scope_token = None


def cancel_windows_call(thread_id: int) -> None:
    """Request cancellation without joining the worker's Windows COM apartment."""
    import ctypes

    cancel = ctypes.WinDLL("ole32").CoCancelCall
    cancel.argtypes = (ctypes.c_ulong, ctypes.c_ulong)
    cancel.restype = ctypes.c_long
    result = cancel(thread_id, 0)
    if result != 0:
        # No pending cancellable call is normal between requests or during local
        # provider cleanup. Keep its code available without flooding warnings.
        logger.debug(
            "Windows cancellation request returned 0x%08X", result & 0xFFFFFFFF
        )


@contextmanager
def socket_read(
    control: ReadControl, label: str, connection: socket.socket
) -> Iterator[ReadOperation]:
    """Bound and release one newly created, exclusively owned Python socket.

    Never pass a borrowed native socket or a shared connection here. Shutdown
    and close are both needed to wake Windows timed receives. The owning thread
    finishes cleanup after the monitor is joined, and any close failure is fatal.
    """
    cleanup_error: OSError | None = None

    def interrupt() -> None:
        nonlocal cleanup_error
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            logger.debug("%s socket was unconnected or already closed", label)
        try:
            connection.close()
        except OSError as error:
            if cleanup_error is None:
                logger.error(
                    "%s socket cancellation could not close its owned connection", label
                )
                cleanup_error = error

    try:
        with control.operation(label, interrupt) as operation:
            connection.settimeout(operation.remaining())
            try:
                yield operation
                operation.check()
            except OSError as error:
                if operation.is_stopped or isinstance(error, TimeoutError):
                    logger.warning("%s reached its stop condition", label)
                    raise ReadStoppedError(f"{label} was stopped") from error
                logger.warning("%s socket operation failed", label)
                raise
    finally:
        try:
            connection.close()
        except OSError as error:
            logger.error("%s could not release its owned socket", label)
            cleanup_error = error
        if cleanup_error is not None:
            raise ClientCleanupError(
                f"{label} socket cleanup failed"
            ) from cleanup_error
