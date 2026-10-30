"""Recognize definite Windows account rejection without exposing provider text."""

from __future__ import annotations

import re

from ..logging import get_logger

logger = get_logger(__name__)

_REJECTED_CODES = {
    0xC000006A,
    0xC000006D,
    0xC000006E,
    0xC000006F,
    0xC0000070,
    0xC0000071,
    0xC0000072,
    0xC0000193,
    0xC0000224,
    0xC0000234,
    0x8007052E,
    0x8009030C,
    # HRESULT_FROM_WIN32: expired password, disabled/expired account,
    # required password change, and an already locked account.
    0x80070532,
    0x80070533,
    0x80070701,
    0x80070773,
    0x80070775,
}
_WRAPPED_REJECTION = re.compile(
    r"(?<![0-9a-z])(?:"
    + "|".join(
        spelling
        for code in sorted(_REJECTED_CODES)
        for spelling in (f"(?:0x)?{code:08x}", str(code - 2**32), str(code))
    )
    + r")(?![0-9a-z])",
    re.IGNORECASE,
)


def is_windows_credential_rejection(error: BaseException) -> bool:
    """Cover native HRESULTs, DCOM status and an SSPI error wrapped by ldap3.

    Access denied to an object or a query is deliberately absent: that does not
    establish a rejected account. The caller logs the decision without logging
    potentially secret authentication packets or arbitrary exception fields.
    """
    codes = [getattr(error, "hresult", None)]
    reader = getattr(error, "get_error_code", None)
    if callable(reader):
        try:
            codes.append(reader())
        except Exception:
            logger.debug(
                "The provider could not expose its numeric authentication status"
            )
    details = getattr(error, "excepinfo", None)
    if isinstance(details, tuple) and details:
        codes.append(details[-1])
    if error.args:
        codes.append(error.args[0])
    if any(
        isinstance(code, int) and code & 0xFFFFFFFF in _REJECTED_CODES for code in codes
    ):
        return True
    # ldap3's Windows SSPI shim wraps the original exception in LDAPBindError,
    # so its HRESULT can survive only in the text. Match definite status names
    # or complete known codes; never interpret generic "access denied" as a
    # bad password and never write this provider text to diagnostics here.
    text = str(error).casefold()
    return bool(_WRAPPED_REJECTION.search(text)) or any(
        marker in text
        for marker in (
            "sec_e_logon_denied",
            "status_logon_failure",
            "status_account_disabled",
            "logon attempt failed",
            "account is disabled",
            "password has expired",
        )
    )
