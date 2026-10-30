"""Remember, for a whole run, that the supplied sign-in details were rejected.

Why this exists: the owner's rule is to stop after a single invalid sign-in.
Each client already stops retrying its own connection after a rejection. But a
run visits many computers, and without a shared memory every computer would
try the same wrong password again. In the lab, one wrong password cost dozens
of failed sign-ins against the same account in a single run.

How it works: a collector creates one ``CredentialGuard`` per run and hands it
to every client that signs in. Before signing in, a client calls
``check_before_sign_in``. When a client sees a definite rejection, it calls
``record_rejection``. The guard then runs the stop actions the collector
registered, such as stopping the queue of computers, and every later
``check_before_sign_in`` refuses with ``CredentialsRejectedError``.

Only definite rejections count: a wrong password, or an account that is
unknown, disabled, locked or expired. "Access denied" to an object, or a SQL
Server "login failed", does not prove the password was wrong. A correct account
that simply lacks access produces those too, so they never stop a run.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from threading import Lock

from ..logging import get_logger
from .identity_errors import is_windows_credential_rejection
from .kerberos import KerberosAcquisitionError

logger = get_logger(__name__)

CREDENTIALS_REJECTED_REASON = (
    "The supplied sign-in details were rejected; no further sign-ins were attempted"
)


class CredentialsRejectedError(RuntimeError):
    """Raised instead of signing in once the run's sign-in details were rejected."""


class CredentialCheck(enum.Enum):
    """The result of signing in once, before any computer is visited."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    # The domain controller could not be reached, so nothing was checked.
    UNCHECKED = "unchecked"
    # No sign-in details were typed in; the logged-on Windows session is used.
    NOT_NEEDED = "not needed"


class CredentialGuard:
    """One run's shared record of whether its sign-in details were rejected.

    Safe to use from several worker threads at once. The first rejection wins;
    later reports are ignored because the run is already stopping.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._rejected_by: str | None = None
        self._stop_actions: list[Callable[[], None]] = []

    @property
    def is_rejected(self) -> bool:
        """True once any client has reported a definite rejection."""
        with self._lock:
            return self._rejected_by is not None

    @property
    def rejected_by(self) -> str | None:
        """A short description of where the rejection happened, for messages."""
        with self._lock:
            return self._rejected_by

    def add_stop_action(self, action: Callable[[], None]) -> None:
        """Run *action* once when the first rejection is recorded.

        If a rejection was already recorded, *action* runs straight away, so a
        collector that registers late still stops.
        """
        with self._lock:
            is_already_rejected = self._rejected_by is not None
            if not is_already_rejected:
                self._stop_actions.append(action)
        if is_already_rejected:
            logger.debug("The sign-in details were already rejected; stopping now")
            action()

    def check_before_sign_in(self, purpose: str) -> None:
        """Refuse *purpose* (for example "SMB sign-in on host") after a rejection."""
        with self._lock:
            rejected_by = self._rejected_by
        if rejected_by is None:
            return  # Nothing has been rejected, so the caller may sign in.
        logger.warning(
            "Not attempting %s: %s already rejected the sign-in details",
            purpose,
            rejected_by,
        )
        raise CredentialsRejectedError(CREDENTIALS_REJECTED_REASON)

    def record_rejection(self, rejected_by: str) -> None:
        """Remember the first definite rejection and stop the run.

        *rejected_by* says where it happened, for example "the domain
        controller" or "WMI on ps1-sms.mayyhem.com". It must not contain secrets.
        """
        with self._lock:
            if self._rejected_by is not None:
                logger.debug(
                    "%s also rejected the sign-in details; the run is already stopping",
                    rejected_by,
                )
                return
            self._rejected_by = rejected_by
            actions = list(self._stop_actions)
            self._stop_actions.clear()
        logger.error(
            "%s rejected the supplied sign-in details; stopping the whole run so "
            "the account is not tried again",
            rejected_by,
        )
        # Run the stop actions outside the lock: one of them may wake worker
        # threads that immediately call check_before_sign_in.
        for action in actions:
            action()


def is_rejected_sign_in(error: BaseException) -> bool:
    """True when *error* proves the account or password itself was refused.

    Covers Windows status codes (wrong password, disabled, locked or expired
    account) and Kerberos replies with the matching reasons. Directory
    rejections are recognized by the directory client itself, which can read
    the domain controller's detailed reason.
    """
    if isinstance(error, CredentialsRejectedError):
        return True
    if isinstance(error, KerberosAcquisitionError):
        return error.is_rejected_identity
    return is_windows_credential_rejection(error)
