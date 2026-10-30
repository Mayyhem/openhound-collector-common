"""A bounded scheduler's target list, with duplicate and completion tracking.

Targets are opaque strings. The caller supplies a stable identity rule: a SCCM
hostname and a SQL endpoint with its port/instance must not share a rule by
accident. A discovering worker submits new work before releasing its own slot.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from threading import Condition, Event

from ..logging import get_logger

logger = get_logger(__name__)


class WorkQueue:
    """Track queued, active and intentionally unstarted targets under one lock."""

    def __init__(
        self,
        identity: Callable[[str], str] = str.lower,
        *,
        stop_event: Event | None = None,
    ) -> None:
        self._identity = identity
        self._condition = Condition()
        self._pending: deque[str] = deque()
        self._seen: set[str] = set()
        self._active: dict[str, str] = {}
        self._unstarted: list[str] = []
        self.stop_event = stop_event if stop_event is not None else Event()
        self.stop_reason: str | None = None

    def submit(self, target: str | None) -> bool:
        """Add one nonblank target once; never start new work after a stop."""
        if target is None or not target.strip():
            logger.debug("Skipping a blank collection target")
            return False
        cleaned = target.strip()
        key = self._identity(cleaned)
        with self._condition:
            if self.stop_event.is_set():
                logger.warning(
                    "Not scheduling %s because collection is stopping", cleaned
                )
                return False
            if key in self._seen:
                logger.debug("Collection target %s is already registered", cleaned)
                return False
            self._seen.add(key)
            self._pending.append(cleaned)
            self._condition.notify_all()
            logger.debug("Queued collection target %s", cleaned)
            return True

    def next(self) -> str | None:
        """Wait for work, a stop, or a state with no queued or active targets."""
        with self._condition:
            while True:
                if self.stop_event.is_set():
                    self._unstarted.extend(self._pending)
                    self._pending.clear()
                    return None
                if self._pending:
                    target = self._pending.popleft()
                    self._active[self._identity(target)] = target
                    return target
                if not self._active:
                    return None  # No worker remains that can discover another target.
                self._condition.wait(timeout=0.1)
                # An ordinary temporary gap is a wait, not completed collection.

    def complete(self, target: str) -> None:
        """Release exactly one active target, after its completion callback."""
        key = self._identity(target.strip())
        with self._condition:
            if key not in self._active:
                logger.error(
                    "Target %s was completed without an active queue slot", target
                )
                raise ValueError("Cannot complete an inactive collection target")
            del self._active[key]
            self._condition.notify_all()

    def in_flight(self) -> int:
        """Return the number of actual running target jobs, not queued futures."""
        with self._condition:
            return len(self._active)

    def stop(self, reason: str) -> None:
        """Stop new work, wake waiting workers, and retain an unstarted inventory."""
        if not reason.strip():
            logger.error("Stopping collection requires a reason")
            raise ValueError("Stopping collection requires a reason")
        with self._condition:
            if self.stop_event.is_set():
                return  # The first stop reason identifies the initiating event.
            self.stop_reason = reason
            self.stop_event.set()
            self._unstarted.extend(self._pending)
            self._pending.clear()
            self._condition.notify_all()
            logger.warning("Stopping target scheduling: %s", reason)

    def unstarted_targets(self) -> tuple[str, ...]:
        """Return targets removed from the pending list when collection stopped."""
        with self._condition:
            return tuple(self._unstarted)
