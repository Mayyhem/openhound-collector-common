"""Keep authentication packet/key dumps out of provider diagnostics."""

from collections.abc import Iterator
from contextlib import contextmanager
import logging
import threading


class _AuthenticationDetails(logging.Filter):
    """Suppress routine provider detail only for the calling authentication thread."""

    def __init__(self) -> None:
        super().__init__()
        self.thread_id = threading.get_ident()

    def filter(self, record: logging.LogRecord) -> bool:
        # Do not log from a log filter. The caller records safe outcomes; these
        # provider debug dumps can contain new session keys or roastable replies
        # which cannot be redacted by matching the user's original password.
        return record.thread != self.thread_id or record.levelno >= logging.WARNING


@contextmanager
def authentication_diagnostics() -> Iterator[None]:
    """Keep failures visible without emitting raw authentication packets.

    Impacket 0.13.1 logs AS-REP material at DEBUG; ldap3 can log encoded SASL
    requests when its detailed logging is enabled. Scoped filters protect these
    exchanges even when an existing consumer has its own console formatter.
    They do not change logger levels, format, identity, or credential state.
    Overlapping threads own separate filters, removed after their own call.
    """
    selected = [logging.getLogger(name) for name in ("impacket", "ldap3")]
    guard = _AuthenticationDetails()
    for provider in selected:
        provider.addFilter(guard)
    try:
        yield
    finally:
        for provider in selected:
            provider.removeFilter(guard)
