# Generalized from sccm/sccm/src/openhound_sccm/clients/ad.py (the lockout-safe
# LDAP transport×bind waterfall, the result-49 sub-code allow-list, the
# current-user SSPI NTLM shim, and the binary objectSid/objectGUID decoders)
# and the Go reference MSSQLHound/internal/ad/client.go (the
# `(servicePrincipalName=MSSQLSvc/*)` paged enumeration, the
# `(objectClass=computer)` scan-all enumeration, and SID resolution into a
# DomainPrincipal). DC auto-resolution lives in discovery/dns.py.
#
# "Generalize" per design spec §2.1: SCCM's ADClient is a generic LDAP wrapper
# already, but it (a) only exposed `paged_search`, and (b) took only
# user/password creds. This shared version keeps SCCM's proven, lockout-safe
# auto-detection verbatim and adds:
#   - explicit LDAP auth *selection*: user/password, NT-hash (pass-the-hash),
#     base64 KRB-CRED Kerberos ticket (pass-the-ticket), or current-user SSPI;
#   - the MSSQL-shaped query surface: `enumerate_spns`, `enumerate_computers`,
#     `resolve_sid`, `resolve_principal` — each returning plain dicts.
# The SID-search filter is built from a *binary, byte-escaped* objectSid (the Go
# code's `escapeSIDForLDAP` admits it never did this; ldap3 needs it to match).
"""LDAP / Active Directory client for OpenHound collectors.

:class:`AdClient` opens an authenticated ``ldap3`` connection by auto-detecting
the right transport + security envelope, then exposes the queries MSSQL
discovery needs:

  * :meth:`enumerate_spns` — paged ``(servicePrincipalName=<filter>)`` search
    (default ``MSSQLSvc/*``) returning each account's SPNs + identity.
  * :meth:`enumerate_computers` — paged ``(objectClass=computer)`` search for
    the ``--scan-all-computers`` mode.
  * :meth:`resolve_sid` / :meth:`resolve_principal` — SID→object and
    name→object resolution into a flat dict (name, type, SID, etc.).

Authentication is one of (selected by which constructor arg is set):

  * **NTLM** with explicit ``user`` + ``password``.
  * **NTLM pass-the-hash** with ``user`` + ``nt_hash`` (LM:NT or bare NT hex).
  * **Kerberos pass-the-ticket** from a base64 KRB-CRED (``.kirbi``) — loaded
    into run-local ticket material used directly on this ldap3 connection.
  * **Current-user SSPI** (Windows only) — the logged-on user's session, no
    explicit credentials. Gated behind ``sys.platform == "win32"``.

The transport waterfall (LDAPS:636 → LDAP:389+StartTLS → plain LDAP:389) and
the bind waterfall (NTLM → SimpleBind → GSSAPI) are ported from the SCCM client
and are **lockout-safe**: only AD's credential-class result-49 sub-codes
(``52e``/``532``/``533``/``701``/``773``/``775``) stop the chain and propagate;
protocol-level rejections (``strongerAuthRequired``, CBT mismatch
``80090346``, TLS / connect failures) are returned *before* the password is
validated, so retrying another transport profile after one of those does not
advance ``badPwdCount``.
"""

from __future__ import annotations

import importlib
import ipaddress
import socket
import struct
import sys
import time
from collections.abc import Callable, Generator
from contextlib import closing
from threading import Lock

from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Optional

from ldap3 import (
    ALL,
    AUTO_BIND_NO_TLS,
    AUTO_BIND_NONE,
    AUTO_BIND_TLS_BEFORE_BIND,
    KERBEROS,
    NTLM,
    SASL,
    SUBTREE,
    Connection,
    Server,
)
from ldap3.core.exceptions import LDAPBindError, LDAPCommunicationError, LDAPException
from ldap3.core.results import RESULT_SUCCESS
from ldap3.utils.conv import escape_filter_chars

# Importing the shared logging module registers the VERBOSE level and the
# ``Logger.verbose`` method we use below (per-search trace). Imported for that
# side effect; ``noqa`` because the name itself is unused here.
from ..logging.log_context import get_logger
from ..collection import OperationResult
from ..discovery.dns import dc_hostname_for_address
from ..discovery.network import active_resolver
from .auth import split_user_domain
from .operations import ClientCleanupError, ReadControl, ReadOperation, ReadStoppedError
from .identity_errors import is_windows_credential_rejection
from .windows_ldap import WindowsLdapClient, WindowsLdapError
from ..proxy import active_proxy
from .kerberos import (
    CredentialInputError,
    KerberosAcquisitionError,
    KerberosCredentials,
    load_kerberos_credentials,
    validate_kerberos_identity,
    validate_secret_sources,
)

# ENCRYPT / TLS_CHANNEL_BINDING were added in ldap3 2.10.2rc4 (our floor). Newer
# DCs that enforce LDAP signing or channel binding need these constants. Try-
# import so the file still loads against an older ldap3 in a mid-upgrade venv.
try:
    # The suppression below is needed because types-ldap3 targets 2.9.13 while this package
    # pins ldap3 2.10.2rc4 -- the first release to export these two. They exist at runtime;
    # the stubs simply lag. Keeping the stubs is still worth it: they type the rest of
    # ldap3, one of the most-used APIs in this library.
    from ldap3 import ENCRYPT, TLS_CHANNEL_BINDING  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - belt & braces for older ldap3
    ENCRYPT = "ENCRYPT"
    TLS_CHANNEL_BINDING = "TLS_CHANNEL_BINDING"

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Optional-backend capability gates. Integrated Kerberos (SASL GSSAPI) needs an
# OS Kerberos backend (gssapi on POSIX, winkerberos on Windows). Current-user
# SSPI NTLM needs pywin32. We probe once at import so planning can skip a profile
# cleanly rather than crashing inside ldap3's SASL state machine.
# ---------------------------------------------------------------------------
def _integrated_auth_available() -> bool:
    try:
        importlib.import_module("gssapi")
        return True
    except ImportError:
        # No POSIX GSSAPI — try the Windows backend next.
        pass
    try:
        importlib.import_module("winkerberos")
        return True
    except ImportError:
        # Neither backend present — integrated Kerberos is unavailable.
        return False


_INTEGRATED_AUTH_AVAILABLE = _integrated_auth_available()


def _current_user_ntlm_available() -> bool:
    if sys.platform != "win32":
        # SSPI is a Windows-only API. Gate per the task requirement.
        return False
    try:
        importlib.import_module("sspi")
        importlib.import_module("sspicon")
        importlib.import_module("win32security")
        return True
    except ImportError:
        # pywin32 not installed — current-user SSPI NTLM is unavailable.
        return False


_CURRENT_USER_NTLM_AVAILABLE = _current_user_ntlm_available()


# AD returns LDAP result code 49 (invalidCredentials) with a ``data XXXX`` tag.
# Only the credential-class codes below increment badPwdCount, so only these
# stop the waterfall (retrying another transport would just rack up lockouts).
# 52e bad password · 532 expired · 533 disabled · 701 acct expired ·
# 773 must change · 775 already locked.
_CREDENTIAL_FAILURE_SUBCODES = {"52e", "532", "533", "701", "773", "775"}


def _bind_error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}".lower()


def _is_credential_failure(exc: BaseException) -> bool:
    """True for a bind error tied to the credential itself (bad/locked/expired/
    disabled). Returning True stops the waterfall — retrying another transport
    would only advance badPwdCount without changing the outcome."""
    text = _bind_error_text(exc)
    # Providers write this label as either invalidCredentials or Invalid
    # Credentials. Spacing must not turn the same rejected password into a retry.
    compact_text = "".join(text.split())
    if "invalidcredentials" not in compact_text:
        # The bind caller logs the resulting failure or retry. Classification
        # itself neither opens a connection nor hides a failed operation.
        return False
    return any(f"data {code}" in text for code in _CREDENTIAL_FAILURE_SUBCODES)


def _is_ip_address(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _reverse_dns_hostname(value: Optional[str]) -> Optional[str]:
    """Reverse-resolve an IP to a hostname so GSSAPI can build an LDAP SPN.

    Kerberos SPNs require hostnames, not IPs (Go does the same LookupAddr).
    Returns None when *value* isn't an IP or reverse DNS yields nothing usable.
    """
    if not _is_ip_address(value):
        return None
    ip_text = value.strip().strip("[]")  # type: ignore[union-attr]
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_text)
    except OSError as exc:
        logger.debug("Reverse DNS lookup for %s failed: %s", ip_text, exc)
        return None
    for candidate in (hostname, *aliases):
        candidate = candidate.strip().rstrip(".")
        if candidate and not _is_ip_address(candidate):
            return candidate
    # Reverse DNS only returned IP-shaped names — useless for an SPN.
    return None


# ---------------------------------------------------------------------------
# Binary SID / GUID decoders (verbatim intent from SCCM's bytes_to_sid /
# bytes_to_guid). objectSid comes off the wire as a binary blob; we decode to
# the canonical S-1-... string and, separately, byte-escape it back into a
# binary LDAP filter for SID searches.
# ---------------------------------------------------------------------------
def bytes_to_sid(value: Any) -> Optional[str]:
    """Convert a binary objectSid (8+ bytes) into ``S-1-...`` string form.

    ldap3 sometimes returns the SID already formatted as a string; pass through.
    """
    if value is None:
        return None
    if isinstance(value, str):
        # Already a formatted "S-1-..." string from ldap3 — nothing to decode.
        return value
    if not isinstance(value, (bytes, bytearray)) or len(value) < 8:
        return None
    revision = value[0]
    sub_authority_count = value[1]
    identifier_authority = int.from_bytes(value[2:8], "big")
    sub_authorities = [
        struct.unpack("<I", value[8 + i * 4 : 8 + i * 4 + 4])[0]
        for i in range(sub_authority_count)
    ]
    parts = [str(revision), str(identifier_authority)] + [
        str(sa) for sa in sub_authorities
    ]
    return "S-" + "-".join(parts)


def bytes_to_guid(value: Any) -> Optional[str]:
    """Convert a binary objectGUID (16 bytes) into the canonical 8-4-4-4-12 string."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if not isinstance(value, (bytes, bytearray)) or len(value) != 16:
        return None
    # objectGUID is little-endian for the first three groups.
    return "{}-{}-{}-{}-{}".format(
        value[0:4][::-1].hex(),
        value[4:6][::-1].hex(),
        value[6:8][::-1].hex(),
        value[8:10].hex(),
        value[10:16].hex(),
    )


def sid_to_ldap_filter_bytes(sid: str) -> Optional[str]:
    """Encode a ``S-1-...`` SID string into a binary, byte-escaped LDAP filter.

    The Go reference searches ``(objectSid=<string>)`` and its own comment
    admits that doesn't actually work — AD stores objectSid as binary. ldap3
    matches reliably only against the binary form written as ``\\xx\\xx...``.
    Returns None for a malformed SID (so the caller can fall back / skip).
    """
    try:
        parts = sid.strip().split("-")
        # Expect: ['S', revision, authority, sub1, sub2, ...]
        revision = int(parts[1])
        identifier_authority = int(parts[2])
        sub_authorities = [int(p) for p in parts[3:]]
    except (IndexError, ValueError):
        logger.warning("sid_to_ldap_filter_bytes: malformed SID %r", sid)
        return None
    blob = bytes([revision, len(sub_authorities)])
    blob += identifier_authority.to_bytes(6, "big")
    for sub in sub_authorities:
        blob += struct.pack("<I", sub)
    # Escape every byte as \xx so the binary survives the LDAP filter grammar.
    return "".join(f"\\{b:02x}" for b in blob)


# ---------------------------------------------------------------------------
# Current-user SSPI NTLM shim (Windows). Ported from SCCM's
# _SSPICurrentUserNtlmClient: lets ldap3 perform an NTLM bind backed by the
# logged-on Windows session (no password handled by us).
# ---------------------------------------------------------------------------
class _SSPICurrentUserNtlmClient:
    """ldap3 NTLM client shim backed by the current Windows SSPI credentials."""

    def __init__(self) -> None:
        import sspi

        self._auth = sspi.ClientAuth("NTLM")
        self._challenge: Optional[bytes] = None

    @staticmethod
    def _buffer_bytes(sec_buffer) -> bytes:
        if not sec_buffer or len(sec_buffer) == 0:
            return b""
        return bytes(sec_buffer[0].Buffer or b"")

    def create_negotiate_message(self) -> bytes:
        _, sec_buffer = self._auth.authorize(None)
        return self._buffer_bytes(sec_buffer)

    def parse_challenge_message(self, message: bytes) -> bool:
        self._challenge = bytes(message)
        return True

    def create_authenticate_message(self) -> bytes:
        if self._challenge is None:
            return b""
        _, sec_buffer = self._auth.authorize(self._challenge)
        return self._buffer_bytes(sec_buffer)

    def seal(self, message: bytes) -> bytes:
        encrypted, trailer = self._auth.encrypt(message)
        return trailer + encrypted

    def unseal(self, sealed_message: bytes) -> bytes:
        import sspicon

        sizes = self._auth.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
        trailer_size = int(sizes["SecurityTrailer"])
        trailer = sealed_message[:trailer_size]
        encrypted = sealed_message[trailer_size:]
        return self._auth.decrypt(encrypted, trailer)


# ---------------------------------------------------------------------------
# Auth selection + bind-attempt profile data classes.
# ---------------------------------------------------------------------------
@dataclass
class LdapAuth:
    """Which LDAP credential to bind with. Exactly one mode is selected by the
    first set field, in priority order: ticket → nt_hash → password → SSPI.

    * ``username`` + ``password`` → NTLM bind.
    * ``username`` + ``nt_hash`` (``LM:NT`` or bare 32-hex NT) → NTLM PtH bind.
    * ``kerberos_ticket`` (base64 KRB-CRED) → connection-local Kerberos bind.
    * none of the above → current-user SSPI (Windows) or anonymous.
    """

    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    nt_hash: Optional[str] = field(default=None, repr=False)
    kerberos_ticket: Optional[str] = field(default=None, repr=False)
    kerberos_ccache: str | None = field(default=None, repr=False)
    kerberos_keytab: str | None = field(default=None, repr=False)
    kerberos_realm: str | None = None
    kerberos_credentials: KerberosCredentials | None = field(default=None, repr=False)
    kdc_host: str | None = None

    def __post_init__(self) -> None:
        validate_secret_sources(
            password=self.password,
            nt_hash=self.nt_hash,
            ticket=self.kerberos_ticket,
            ccache=self.kerberos_ccache,
            keytab=self.kerberos_keytab,
            loaded_credentials=self.kerberos_credentials,
        )
        if self.kerberos_credentials is not None:
            validate_kerberos_identity(
                self.kerberos_credentials, self.username, self.kerberos_realm
            )

    def uses_explicit_kerberos(self) -> bool:
        """Whether a supplied credential source/realm replaces ambient OS Kerberos."""
        return any(
            value is not None
            for value in (
                self.kerberos_ticket,
                self.kerberos_ccache,
                self.kerberos_keytab,
                self.kerberos_credentials,
                self.kerberos_realm,
            )
        )


@dataclass(frozen=True)
class _BindAttempt:
    """One (transport, hardening, bind-mode) tuple in the waterfall."""

    label: str
    use_ssl: bool
    port: int
    start_tls: bool
    session_security: bool  # NTLM sign+seal — requires NTLM credentials
    channel_binding: bool  # TLS CBT — requires TLS + NTLM credentials
    auth_mode: str  # "ntlm" | "ntlm_hash" | "kerberos" | "sspi_ntlm" | "anonymous"


class AdClient:
    """ldap3 wrapper with a lockout-safe transport/bind waterfall + the AD
    queries MSSQL discovery needs. See the module docstring for auth modes.

    Connect lazily: the first query (or :meth:`bind`) opens the connection.
    SID/name resolutions are cached so repeated lookups don't re-hit the DC.
    """

    def __init__(
        self,
        domain: str,
        dc: Optional[str] = None,
        auth: Optional[LdapAuth] = None,
        *,
        port: Optional[int] = None,
        on_query: Callable[[OperationResult], None] | None = None,
        native_fallback: ReadControl | None = None,
        read_control: ReadControl | None = None,
    ) -> None:
        self.domain = domain
        self.dc = dc
        self.auth = auth or LdapAuth()
        self.port = port
        self.on_query = on_query
        self.last_query_result: OperationResult | None = None
        self.native_fallback = native_fallback
        self.read_control = read_control
        if read_control is not None and not isinstance(read_control, ReadControl):
            logger.error("LDAP read limits require validated read controls")
            raise ValueError("LDAP read limits require ReadControl")
        self._opening_conn: Connection | None = None
        self._bind_operation: ReadOperation | None = None
        self._search_operation: ReadOperation | None = None
        self._search_guard = Lock()
        if native_fallback is not None and not isinstance(native_fallback, ReadControl):
            logger.error("Native LDAP fallback requires validated read controls")
            raise ValueError("Native LDAP fallback requires ReadControl")
        self.selected_backend = "ldap3"
        self._credential_failure: Exception | None = None
        self.base_dn = (
            ",".join(f"DC={part}" for part in domain.split(".")) if domain else ""
        )
        self._conn: Optional[Connection] = None
        self._kerberos_credentials = self.auth.kerberos_credentials
        self._sid_cache: dict[str, Optional[dict[str, Any]]] = {}
        self._name_cache: dict[str, Optional[dict[str, Any]]] = {}

    # ------------------------------------------------------------------ bind --

    def bind(self) -> Connection:
        """Bind with the optional whole-attempt budget, preserving default policy."""
        if self.read_control is None:
            return self._bind()  # Existing consumers keep their timeout behavior.
        operation = None
        try:
            operation = self.read_control.operation("LDAP bind", self._interrupt)
            with operation:
                self._bind_operation = operation
                return self._bind()
        except BaseException as error:
            if isinstance(error, ReadStoppedError) or (
                operation is not None and operation.is_stopped
            ):
                logger.warning(
                    "LDAP bind stopped; refusing further authentication attempts"
                )
                self.close()
                if isinstance(error, ClientCleanupError):
                    raise  # Failed cleanup must remain a fatal run failure.
                raise ReadStoppedError("LDAP bind was stopped") from error
            raise
        finally:
            self._bind_operation = None

    def _bind(self) -> Connection:
        if self._credential_failure is not None:
            logger.warning(
                "LDAP credentials were already rejected; refusing another submission"
            )
            raise self._credential_failure
        if self._conn is not None and self._conn.bound:
            return self._conn

        attempts = self._build_attempt_plan()
        attempts, host = self._prepare_attempts_and_host(attempts)
        self._log_credential_summary(attempts)

        last_exc: Optional[BaseException] = None
        for attempt in attempts:
            try:
                self._conn = self._open_attempt(host=host, attempt=attempt)
                logger.info(
                    "LDAP connected: %s:%d (auth=%s, profile=%s)",
                    host,
                    attempt.port,
                    attempt.auth_mode,
                    attempt.label,
                )
                return self._conn
            except (ClientCleanupError, ReadStoppedError):
                logger.error(
                    "LDAP binding stopped or cleanup failed; no other profile will be tried"
                )
                raise
            except (CredentialInputError, KerberosAcquisitionError) as error:
                self._credential_failure = error
                logger.error(
                    "LDAP cannot use the selected explicit Kerberos identity; stopping attempts"
                )
                raise
            except LDAPException as exc:
                if _is_credential_failure(exc) or is_windows_credential_rejection(exc):
                    self._credential_failure = exc
                    # Bad/locked/expired credential — stop now to avoid lockout.
                    logger.error(
                        "LDAP bind via %s failed with a credential error: %s",
                        attempt.label,
                        exc,
                    )
                    raise
                last_exc = exc
                logger.debug(
                    "LDAP bind via %s failed (%s); trying next profile",
                    attempt.label,
                    exc,
                )
                continue
            except OSError as exc:
                # Connect/TLS failure — no auth attempted, safe to fall through.
                last_exc = exc
                logger.debug(
                    "LDAP transport to %s:%d (%s) failed: %s; trying next profile",
                    host,
                    attempt.port,
                    attempt.label,
                    exc,
                )
                continue
            except Exception as exc:
                if is_windows_credential_rejection(exc):
                    self._credential_failure = exc
                    logger.error(
                        "Windows rejected the LDAP identity; stopping authentication attempts"
                    )
                    raise
                if attempt.auth_mode in ("kerberos", "sspi_ntlm"):
                    # Integrated-auth backends raise non-LDAP exceptions (SSPI /
                    # GSSAPI errors); treat as a soft failure and keep going.
                    last_exc = exc
                    logger.debug(
                        "LDAP bind via %s failed (%s); trying next profile",
                        attempt.label,
                        exc,
                    )
                    continue
                # Unexpected failure on an explicit-cred path — surface it.
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("LDAP connection failed before any bind was attempted")

    def _interrupt(self) -> None:
        """Shut down only this client's current or opening Python LDAP socket."""
        for connection in (self._conn, self._opening_conn):
            owned_socket = getattr(connection, "socket", None)
            if owned_socket is None:
                continue  # Socket creation may still be in progress.
            try:
                owned_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("LDAP cancellation found an already stopped socket")
            finally:
                # On Windows, shutdown alone does not wake Python's select wait
                # for a socket with a receive timeout. This connection owns the
                # socket; close it too, then let the reading thread release the
                # LDAP connection object. Native WLDAP handles are not closed here.
                owned_socket.close()

    def _release_connection(self, connection: Connection) -> None:
        """Release on the calling thread; monitored consumers require confirmed cleanup."""
        try:
            connection.unbind()
        except Exception as error:
            operation = self._search_operation or self._bind_operation
            owned_socket = getattr(connection, "socket", None)
            if (
                isinstance(error, LDAPCommunicationError)
                and operation is not None
                and operation.is_stopped
                and owned_socket is not None
                and owned_socket.fileno() == -1
            ):
                logger.debug(
                    "Stopped LDAP socket is confirmed closed; no unbind message can be sent"
                )
                return
            if self.read_control is not None:
                logger.error("LDAP connection cleanup failed; the owning run must fail")
                raise ClientCleanupError("LDAP connection cleanup failed") from error
            logger.debug("LDAP connection cleanup failed (%s)", type(error).__name__)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._release_connection(self._conn)
            finally:
                self._conn = None

    def _open_attempt(self, *, host: str, attempt: _BindAttempt) -> Connection:
        """Keep an opening connection reachable until its owning thread releases it."""
        connection = None
        try:
            if self._bind_operation is not None:
                self._bind_operation.check()
            connection = self._open_connection(host=host, attempt=attempt)
            if self._bind_operation is not None:
                self._bind_operation.check()
            return connection
        except BaseException as error:
            opening = (
                self._opening_conn if self._opening_conn is not None else connection
            )
            if self.read_control is not None and opening is not None:
                self._release_connection(opening)
            # Non-monitored constructors retain their existing cleanup policy.
            if isinstance(error, ClientCleanupError):
                raise  # Never replace a failed cleanup with an ordinary stop.
            if self._bind_operation is not None and self._bind_operation.is_stopped:
                raise ReadStoppedError("LDAP bind was stopped") from error
            raise
        finally:
            self._opening_conn = None

    # ------------------------------------------------------------- planning --

    def _has_explicit_ntlm(self) -> bool:
        return bool(self.auth.username and self.auth.password)

    def _has_nt_hash(self) -> bool:
        return bool(self.auth.username and self.auth.nt_hash)

    def _has_ticket(self) -> bool:
        return self.auth.uses_explicit_kerberos()

    def _select_auth_modes(self) -> list[str]:
        """Pick the ordered bind modes from the supplied credential."""
        if self._has_ticket():
            # Pass-the-ticket → Kerberos only (no NTLM fallback, mirrors D12).
            return ["kerberos"]
        if self._has_nt_hash():
            # Pass-the-hash → NTLM hash bind only (Go does the same).
            return ["ntlm_hash"]
        if self._has_explicit_ntlm():
            # Password → NTLM (then plain Simple bind handled inside ntlm? no —
            # we mirror Go's NTLM-first; SimpleBind needs TLS and is rarely the
            # winning path against a modern DC, so NTLM/sign-seal covers it).
            return ["ntlm"]
        # No explicit creds: prefer integrated Kerberos, then SSPI NTLM, else
        # anonymous (AD rejects anonymous searches — logged loudly).
        modes: list[str] = []
        if _INTEGRATED_AUTH_AVAILABLE:
            modes.append("kerberos")
        if _CURRENT_USER_NTLM_AVAILABLE:
            modes.append("sspi_ntlm")
        if not modes:
            modes.append("anonymous")
        return modes

    def _build_attempt_plan(self) -> list[_BindAttempt]:
        """Build the ordered (transport × bind-mode) attempt list.

        Transport order (ported from SCCM / matches Go):
          LDAPS:636 → LDAP:389+StartTLS → plain LDAP:389.
        NTLM/PtH profiles get CBT on TLS and sign/seal on the plain leg; the
        integrated/anonymous profiles use plain binds (their own GSS sealing).
        With ``port`` pinned the chain is narrowed to that port.
        """
        modes = self._select_auth_modes()
        pinned = self.port

        def cbt_capable(mode: str) -> bool:
            # Explicit NTLM derives a CBT from the password/hash session key;
            # Kerberos CBT is handled inside ldap3's GSSAPI path. SSPI NTLM via
            # pywin32 doesn't expose the CBT input buffer here.
            return mode in ("ntlm", "ntlm_hash", "kerberos")

        def ntlm_like(mode: str) -> bool:
            # Explicit Kerberos also supplies connection-local sign/seal now.
            return mode in ("ntlm", "ntlm_hash", "sspi_ntlm") or (
                mode == "kerberos" and self.auth.uses_explicit_kerberos()
            )

        def ldaps(mode: str, port: int) -> _BindAttempt:
            cbt = cbt_capable(mode)
            return _BindAttempt(
                label=f"LDAPS{'+CBT' if cbt else ''}",
                use_ssl=True,
                port=port,
                start_tls=False,
                session_security=False,
                channel_binding=cbt,
                auth_mode=mode,
            )

        def starttls(mode: str, port: int) -> _BindAttempt:
            cbt = cbt_capable(mode)
            return _BindAttempt(
                label=f"StartTLS{'+CBT' if cbt else ''}",
                use_ssl=False,
                port=port,
                start_tls=True,
                session_security=False,
                channel_binding=cbt,
                auth_mode=mode,
            )

        def ldap_signed(mode: str, port: int) -> _BindAttempt:
            return _BindAttempt(
                label="LDAP+sign/seal",
                use_ssl=False,
                port=port,
                start_tls=False,
                session_security=True,
                channel_binding=False,
                auth_mode=mode,
            )

        def ldap_plain(mode: str, port: int) -> _BindAttempt:
            return _BindAttempt(
                label="LDAP",
                use_ssl=False,
                port=port,
                start_tls=False,
                session_security=False,
                channel_binding=False,
                auth_mode=mode,
            )

        attempts: list[_BindAttempt] = []
        if pinned is not None:
            for mode in modes:
                if pinned in (636, 3269):
                    attempts.append(ldaps(mode, pinned))
                elif ntlm_like(mode):
                    attempts.append(ldap_signed(mode, pinned))
                    attempts.append(ldap_plain(mode, pinned))
                else:
                    attempts.append(ldap_plain(mode, pinned))
            return attempts

        for mode in modes:
            attempts.append(ldaps(mode, 636))
            if ntlm_like(mode):
                attempts.append(starttls(mode, 389))
                attempts.append(ldap_signed(mode, 389))
            else:
                attempts.append(ldap_plain(mode, 389))
        return attempts

    def _prepare_attempts_and_host(
        self, attempts: list[_BindAttempt]
    ) -> tuple[list[_BindAttempt], str]:
        """Resolve the host to dial and apply the IP-DC Kerberos fallback.

        Kerberos needs a DC *hostname* to build the ``ldap/<dc>`` SPN; an IP DC
        can't (``InitializeSecurityContext`` fails "target unknown"). So when a
        Kerberos profile targets an IP DC:

        1. reverse-DNS the IP and use the hostname if one is found;
        2. else, if current-user SSPI-NTLM is available, **drop the Kerberos
           profiles** and bind via SSPI-NTLM (which needs no SPN);
        3. else warn and try Kerberos anyway (it will most likely fail, but the
           error is clearer than silently doing nothing).

        Ported from the SCCM collector (generalized: no collector-specific CLI /
        env-var names in the messages) so both collectors get the same fallback.
        """
        host = self.dc or self.domain
        modes = {a.auth_mode for a in attempts}
        if "kerberos" not in modes or not _is_ip_address(self.dc):
            return attempts, host

        rdns_hostname = _reverse_dns_hostname(self.dc)
        resolver = active_resolver()
        if (
            rdns_hostname is None
            and self.auth.uses_explicit_kerberos()
            and resolver is not None
        ):
            # A run-selected DNS service can prove the same DC's name even when
            # its reverse zone is absent. Do not guess or switch to another DC.
            rdns_hostname = dc_hostname_for_address(
                self.domain, str(self.dc), resolver=resolver
            )
        if rdns_hostname:
            logger.info(
                "LDAP auth: DNS resolved Kerberos DC IP '%s' to '%s'; "
                "using that hostname to build the LDAP service principal name.",
                self.dc,
                rdns_hostname,
            )
            return attempts, rdns_hostname

        if "sspi_ntlm" in modes:
            attempts = [a for a in attempts if a.auth_mode != "kerberos"]
            logger.info(
                "LDAP auth: DC '%s' is an IP address and reverse DNS did not "
                "return a hostname; skipping Kerberos and using current-user "
                "NTLM via Windows SSPI.",
                self.dc,
            )
            return attempts, host

        logger.warning(
            "LDAP auth: integrated Kerberos is using domain controller '%s', "
            "which is an IP address, and reverse DNS did not return a hostname. "
            "Kerberos/SSPI needs a DC hostname to build the LDAP service "
            "principal name (ldap/<dc-host>); IP addresses commonly fail with "
            "`InitializeSecurityContext: The specified target is unknown or "
            "unreachable`. Supply the DC by hostname (FQDN or NetBIOS name), or "
            "supply explicit credentials to force NTLM.",
            self.dc,
        )
        return attempts, host

    def _log_credential_summary(self, attempts: list[_BindAttempt]) -> None:
        modes = {a.auth_mode for a in attempts}
        if modes == {"anonymous"}:
            logger.warning(
                "LDAP auth: no usable credentials and no integrated backend — "
                "falling back to anonymous bind. AD rejects meaningful searches "
                "from anonymous binds. Supply --ldap-user/--ldap-password, "
                "--ldap-nt-hash, --ldap-ticket, or install winkerberos."
            )
        elif "ntlm_hash" in modes:
            logger.info("LDAP auth: NTLM pass-the-hash as %s", self.auth.username)
        elif "ntlm" in modes:
            logger.info("LDAP auth: NTLM as %s", self.auth.username)
        elif "kerberos" in modes and self._has_ticket():
            logger.info(
                "LDAP auth: explicit Kerberos identity (ticket/cache/keytab or selected realm)"
            )
        elif "kerberos" in modes:
            logger.info("LDAP auth: integrated Kerberos (current OS user TGT)")
        elif "sspi_ntlm" in modes:
            logger.info("LDAP auth: current-user NTLM via Windows SSPI")

    # ------------------------------------------------------- connection open --

    def _open_connection(self, *, host: str, attempt: _BindAttempt) -> Connection:
        """Open and bind one Connection with the requested security settings."""
        server = Server(
            host,
            port=attempt.port,
            use_ssl=attempt.use_ssl,
            get_info=ALL,
            connect_timeout=5,
        )

        kwargs: dict[str, Any] = {
            "auto_bind": AUTO_BIND_TLS_BEFORE_BIND
            if attempt.start_tls
            else AUTO_BIND_NO_TLS,
            "read_only": True,
            "receive_timeout": 30,
            # Never chase referrals: a subtree search at the domain root makes AD
            # return continuation references to other partitions; ldap3 would
            # open new (unreachable) connections to follow them. We only want
            # this DC's own data.
            "auto_referrals": False,
        }

        if attempt.auth_mode == "sspi_ntlm":
            return self._open_current_user_ntlm_connection(
                server=server, attempt=attempt
            )
        if attempt.auth_mode == "kerberos" and self.auth.uses_explicit_kerberos():
            return self._open_explicit_kerberos_connection(
                server=server, attempt=attempt
            )

        if attempt.auth_mode in ("ntlm", "ntlm_hash"):
            kwargs.update(
                {
                    "user": self._ntlm_user(),
                    "password": self._ntlm_secret(attempt.auth_mode),
                    "authentication": NTLM,
                }
            )
        elif attempt.auth_mode == "kerberos":
            # Only the ambient/current-user path reaches the OS GSSAPI provider.
            kwargs.update({"authentication": SASL, "sasl_mechanism": KERBEROS})
        # "anonymous" → leave authentication unset (ldap3 default ANONYMOUS).

        if attempt.session_security:
            kwargs["session_security"] = ENCRYPT
        if attempt.channel_binding and attempt.auth_mode in ("ntlm", "ntlm_hash"):
            kwargs["channel_binding"] = TLS_CHANNEL_BINDING

        try:
            if self.read_control is None:
                return Connection(server, **kwargs)
            # Construct without network work so cancellation can reach the
            # socket during open, TLS, authentication and schema reads. ldap3's
            # documented manual open/start_tls/bind sequence preserves policy.
            kwargs["auto_bind"] = AUTO_BIND_NONE
            connection = Connection(server, **kwargs)
            self._opening_conn = connection
            connection.open(read_server_info=False)
            if attempt.start_tls and not connection.start_tls(read_server_info=False):
                logger.warning("StartTLS before monitored LDAP bind failed")
                raise LDAPBindError("StartTLS before monitored LDAP bind failed")
            if not connection.bind():
                logger.warning("Monitored LDAP bind was rejected")
                raise LDAPBindError(str(connection.result))
            connection.refresh_server_info()
            return connection
        except TypeError as exc:
            # Older ldap3 rejects session_security / channel_binding kwargs.
            if attempt.session_security or attempt.channel_binding:
                raise RuntimeError(
                    "LDAP signing / channel binding requires ldap3 >= 2.10.2rc4 "
                    "(session_security and channel_binding support)."
                ) from exc
            raise

    def _open_explicit_kerberos_connection(
        self, *, server: Server, attempt: _BindAttempt
    ) -> Connection:
        """Use supplied tickets/keys on this connection, including custom LDAP ports."""
        from .ldap_kerberos import bind_explicit_kerberos

        auth = self.auth
        if self._kerberos_credentials is None and any(
            value is not None
            for value in (
                auth.kerberos_ticket,
                auth.kerberos_ccache,
                auth.kerberos_keytab,
            )
        ):
            self._kerberos_credentials = load_kerberos_credentials(
                ticket=auth.kerberos_ticket,
                ccache_file=auth.kerberos_ccache,
                keytab_file=auth.kerberos_keytab,
                username=auth.username,
                realm=auth.kerberos_realm,
            )
        realm = (
            self._kerberos_credentials.realm
            if self._kerberos_credentials
            else (auth.kerberos_realm or self.domain)
        )
        _, username = split_user_domain(auth.username or "", realm)
        connection = Connection(
            server,
            auto_bind=AUTO_BIND_NONE,
            authentication=SASL,
            sasl_mechanism=KERBEROS,
            read_only=True,
            receive_timeout=30,
            auto_referrals=False,
        )
        if self.read_control is not None:
            self._opening_conn = connection
        try:
            connection.open(read_server_info=False)
            if attempt.start_tls and not connection.start_tls(read_server_info=False):
                logger.warning("StartTLS before explicit Kerberos bind failed")
                raise LDAPBindError("StartTLS before Kerberos bind failed")
            bind_explicit_kerberos(
                connection,
                host=str(server.host),
                realm=realm,
                username=username or None,
                password=auth.password,
                nt_hash=auth.nt_hash,
                credentials=self._kerberos_credentials,
                kdc_host=auth.kdc_host or self.dc,
                use_tls=attempt.use_ssl or attempt.start_tls,
            )
            connection.refresh_server_info()
            return connection
        except BaseException:
            if self.read_control is not None:
                raise  # _open_attempt owns monitored failed-bind cleanup.
            try:
                connection.unbind()
            except Exception as error:
                logger.debug(
                    "Failed LDAP bind connection cleanup failed (%s)",
                    type(error).__name__,
                )
            raise

    def _ntlm_user(self) -> str:
        """Build the ``DOMAIN\\user`` string ldap3 NTLM expects."""
        username = self.auth.username or ""
        if "\\" in username or "@" in username:
            # Already qualified — pass through unchanged.
            return username
        if self.domain:
            return f"{self.domain}\\{username}"
        return username

    def _ntlm_secret(self, mode: str) -> Optional[str]:
        """Return the NTLM bind secret: the password, or an ``LM:NT`` hash.

        ldap3 NTLM accepts an ``LM:NT`` formatted password for pass-the-hash.
        We normalize a bare 32-hex NT hash to ``<32 zeros>:<nt>``.
        """
        if mode == "ntlm":
            return self.auth.password
        nt = (self.auth.nt_hash or "").strip()
        if ":" in nt:
            # Already LM:NT form.
            return nt
        # Bare NT hash — prepend an empty LM half so ldap3 treats it as PtH.
        return f"{'0' * 32}:{nt}"

    def _open_current_user_ntlm_connection(
        self, *, server: Server, attempt: _BindAttempt
    ) -> Connection:
        conn = Connection(
            server,
            auto_bind=AUTO_BIND_NONE,
            authentication=NTLM,
            read_only=True,
            receive_timeout=30,
            auto_referrals=False,
            # session_security likewise postdates the 2.9.13 stubs (see the ENCRYPT import).
            session_security=ENCRYPT if attempt.session_security else None,  # type: ignore[call-arg]
        )
        if self.read_control is not None:
            self._opening_conn = conn
        conn.open(read_server_info=False)
        if attempt.start_tls and not conn.start_tls(read_server_info=False):
            error = "StartTLS before current-user NTLM bind failed"
            if conn.last_error:
                error = f"{error}: {conn.last_error}"
            if self.read_control is None:
                conn.unbind()
            # The monitored path releases the connection in _open_attempt.
            raise LDAPBindError(error)
        self._bind_current_user_ntlm(conn)
        conn.refresh_server_info()
        return conn

    def _bind_current_user_ntlm(self, conn: Connection, controls=None) -> None:
        from ldap3.operation.bind import bind_operation

        # ldap3 clears last_error by setting it to None; the stubs declare it `str`.
        conn.last_error = None  # type: ignore[assignment]
        with conn.connection_lock:
            if conn.sasl_in_progress:
                return
            conn.sasl_in_progress = True
            try:
                # Held in a local as well as on the connection: ldap3 reads
                # conn.ntlm_client internally during these binds (hence the assignment),
                # while the three bind_operation calls below take it as an argument. One
                # name for one object, and one suppression instead of four.
                #
                # Typed Any deliberately. ntlm_client is an ldap3 internal the stubs do not
                # declare at all, and bind_operation's stub types its third parameter as
                # `str` — correct for the ordinary SIMPLE/SASL binds, wrong for the SICILY
                # NTLM exchange below, which passes the client object itself.
                ntlm_client: Any = _SSPICurrentUserNtlmClient()
                conn.ntlm_client = ntlm_client  # type: ignore[attr-defined]

                request = bind_operation(
                    conn.version, "SICILY_PACKAGE_DISCOVERY", ntlm_client
                )
                response = conn.post_send_single_response(
                    conn.send("bindRequest", request, controls)
                )
                result = (
                    response[0]
                    if conn.strategy.sync
                    else conn.get_response(response)[1]
                )
                packages = (
                    (result.get("server_creds") or b"")
                    .decode("ascii", errors="ignore")
                    .split(";")
                )
                if "NTLM" not in packages:
                    raise LDAPBindError("DC did not advertise the NTLM Sicily package")

                request = bind_operation(
                    conn.version, "SICILY_NEGOTIATE_NTLM", ntlm_client
                )
                response = conn.post_send_single_response(
                    conn.send("bindRequest", request, controls)
                )
                result = (
                    response[0]
                    if conn.strategy.sync
                    else conn.get_response(response)[1]
                )

                if result and result.get("result") == RESULT_SUCCESS:
                    request = bind_operation(
                        conn.version,
                        "SICILY_RESPONSE_NTLM",
                        ntlm_client,
                        result.get("server_creds"),
                    )
                    response = conn.post_send_single_response(
                        conn.send("bindRequest", request, controls)
                    )
                    result = (
                        response[0]
                        if conn.strategy.sync
                        else conn.get_response(response)[1]
                    )

                conn.result = result
                conn.bound = bool(result and result.get("result") == RESULT_SUCCESS)
                if not conn.bound:
                    description = result.get("description") if result else None
                    message = result.get("message") if result else None
                    conn.last_error = (
                        description or message or "current-user NTLM bind failed"
                    )
                    raise LDAPBindError(conn.last_error)
            except LDAPException:
                raise
            except Exception as ex:
                raise LDAPBindError(
                    f"current-user NTLM via Windows SSPI failed: {ex}"
                ) from ex
            finally:
                conn.sasl_in_progress = False

    # ---------------------------------------------------------- paged search --

    def _can_use_native_fallback(self, error: BaseException) -> bool:
        """Never change identities, retry rejected credentials or repeat partial data."""
        if self.native_fallback is None:
            return False  # Existing consumers do not select this fallback.
        if isinstance(error, (ReadStoppedError, ClientCleanupError)):
            logger.warning(
                "Skipping native LDAP fallback after a stop or cleanup failure"
            )
            return False
        if sys.platform != "win32" or active_proxy() is not None:
            logger.debug(
                "Skipping native LDAP fallback: it requires direct Windows networking"
            )
            return False
        if any(
            value is not None
            for value in (
                self.auth.username,
                self.auth.password,
                self.auth.nt_hash,
                self.auth.kerberos_ticket,
                self.auth.kerberos_ccache,
                self.auth.kerberos_keytab,
                self.auth.kerberos_realm,
                self.auth.kerberos_credentials,
            )
        ):
            logger.debug(
                "Skipping native LDAP fallback: an explicit identity was selected"
            )
            return False
        code = getattr(error, "hresult", None)
        rejected = (
            self._credential_failure is not None
            or _is_credential_failure(error)
            or "invalidcredentials" in _bind_error_text(error)
            or is_windows_credential_rejection(error)
        )
        if rejected:
            logger.warning("Skipping native LDAP fallback after credential rejection")
            return False
        eligible = isinstance(
            error, (OSError, LDAPCommunicationError, LDAPBindError, ImportError)
        ) or isinstance(code, int)
        if not eligible:
            logger.debug(
                "Skipping native LDAP fallback for a non-transport/non-authentication error"
            )
        return eligible

    def _native_entries(
        self,
        search_filter: str,
        attributes: list[str],
        base: str,
        scope: Literal["BASE", "LEVEL", "SUBTREE"],
        size_limit: int,
        paged_size: int,
        controls: list[str] | None,
    ) -> Generator[dict[str, Any], None, None]:
        """Preserve the existing attribute converter and keep native cleanup local."""
        if controls:
            logger.warning(
                "Native Windows LDAP does not support these additional search controls"
            )
            raise LDAPException(
                "Native Windows LDAP fallback cannot discard search controls"
            )
        if self.native_fallback is None:
            raise RuntimeError("Native Windows LDAP was not selected")
        client = WindowsLdapClient(
            self.dc or self.domain, self.port or 389, self.native_fallback
        )
        if self.selected_backend != "windows":
            logger.warning(
                "Using current-user Windows LDAP after eligible ldap3 failure"
            )
        else:
            logger.debug("Reusing the selected current-user Windows LDAP backend")
        self.selected_backend = "windows"
        try:
            with closing(
                client.search(
                    search_filter, attributes, base, scope, size_limit, paged_size
                )
            ) as entries:
                for entry in entries:
                    yield self._entry_to_dict(entry)
        except WindowsLdapError as error:
            if error.code == 49:
                logger.warning(
                    "Windows LDAP rejected the current identity; no further submissions will be made"
                )
                self._credential_failure = error
            raise

    def paged_search(
        self,
        search_filter: str,
        attributes: list[str],
        base: Optional[str] = None,
        scope: Literal["BASE", "LEVEL", "SUBTREE"] = SUBTREE,
        size_limit: int = 0,
        paged_size: int = 1000,
        controls: Optional[list[str]] = None,
    ) -> Iterable[dict[str, Any]]:
        """Read pages under one optional budget, including bind and result cleanup."""
        rows = self._paged_search(
            search_filter, attributes, base, scope, size_limit, paged_size, controls
        )
        if self.read_control is None:
            yield from rows
            return  # Existing consumers keep their search timeout policy.
        if not self._search_guard.acquire(blocking=False):
            logger.error("An LDAP client cannot run overlapping searches")
            raise RuntimeError("An LDAP client cannot run overlapping searches")
        operation = None
        try:
            operation = self.read_control.operation("LDAP search", self._interrupt)
            with operation, closing(rows):
                self._search_operation = operation
                for row in rows:
                    operation.check()
                    yield row
                operation.check()
        except BaseException as error:
            if isinstance(error, ReadStoppedError) or (
                operation is not None and operation.is_stopped
            ):
                logger.warning("LDAP search stopped; closing its owned connection")
                self.close()
                if isinstance(error, ClientCleanupError):
                    raise
                raise ReadStoppedError("LDAP search was stopped") from error
            raise
        finally:
            self._search_operation = None
            self._search_guard.release()

    def _paged_search(
        self,
        search_filter: str,
        attributes: list[str],
        base: Optional[str] = None,
        # Literal rather than str: ldap3 accepts exactly these three, and naming them puts
        # the valid set in the signature where a caller sees it.
        scope: Literal["BASE", "LEVEL", "SUBTREE"] = SUBTREE,
        size_limit: int = 0,
        paged_size: int = 1000,
        controls: Optional[list[str]] = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Yield each matching entry as a dict {attr: value}, decoding SIDs/GUIDs.

        Paged at *paged_size* (1000, matching the Go controls + AD's default
        cap). A server-side error (e.g. ``noSuchObject``) is logged and stops
        iteration rather than raising into the caller's generator.
        """
        base_dn = base or self.base_dn
        logger.verbose("LDAP search: base=%s filter=%s", base_dn, search_filter)
        total = 0
        page = 0
        started = time.monotonic()
        failure: str | None = None
        completed = False
        connection_ready = False
        try:
            if self._credential_failure is not None:
                logger.warning(
                    "LDAP identity was already rejected; refusing another search"
                )
                raise self._credential_failure
            if self.selected_backend == "windows":
                with closing(
                    self._native_entries(
                        search_filter,
                        attributes,
                        base_dn,
                        scope,
                        size_limit,
                        paged_size,
                        controls,
                    )
                ) as entries:
                    for row in entries:
                        total += 1
                        yield row
                completed = True
                return
            conn = self.bind()
            connection_ready = True
            cookie = None
            while True:
                if self._search_operation is not None:
                    self._search_operation.check()
                conn.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attributes,
                    paged_size=paged_size,
                    paged_cookie=cookie,
                    size_limit=size_limit,
                    controls=controls,
                )
                if self._search_operation is not None:
                    self._search_operation.check()
                result = conn.result or {}
                if not result:
                    logger.warning("LDAP search returned no completion result")
                    failure = "LDAP search returned no completion result"
                    break
                desc = result.get("description")
                if desc and desc.lower() not in ("success", "sizelimitexceeded"):
                    # Server reported an error without raising — surface it.
                    logger.warning(
                        "LDAP search returned %s (base=%s filter=%s): %s",
                        desc,
                        base_dn,
                        search_filter,
                        result.get("message") or "",
                    )
                    failure = "LDAP server rejected the search; see the run logs"
                    break
                page += 1
                total += len(conn.entries)
                for entry in conn.entries:
                    yield self._entry_to_dict(entry)
                if desc and desc.lower() == "sizelimitexceeded" and not size_limit:
                    logger.warning(
                        "LDAP server truncated a search with no caller-selected size limit"
                    )
                    failure = "LDAP server truncated the search; results are incomplete"
                    break
                cookie = (
                    result.get("controls", {})
                    .get("1.2.840.113556.1.4.319", {})
                    .get("value", {})
                    .get("cookie")
                )
                if not cookie or (size_limit > 0 and total >= size_limit):
                    # No continuation cookie — last page consumed.
                    completed = True
                    break
        except ClientCleanupError:
            failure = "LDAP cleanup failed"
            logger.error("LDAP cleanup failed; the owning run must fail")
            raise
        except Exception as exc:
            if (
                total == 0
                and self.selected_backend != "windows"
                and self._can_use_native_fallback(exc)
            ):
                self.close()
                with closing(
                    self._native_entries(
                        search_filter,
                        attributes,
                        base_dn,
                        scope,
                        size_limit,
                        paged_size,
                        controls,
                    )
                ) as entries:
                    for row in entries:
                        total += 1
                        yield row
                completed = True
                return
            failure = "LDAP read failed; see the run logs"
            logger.warning(
                "LDAP search failed (filter=%s, base=%s): %s",
                search_filter,
                base_dn,
                exc,
            )
            if not connection_ready or not isinstance(exc, LDAPException):
                raise  # Keep existing bind failures visible to the caller.
        except BaseException:
            failure = "LDAP read did not finish; see the run logs"
            logger.warning("LDAP read ended before completion")
            raise
        finally:
            result = OperationResult(
                "Windows LDAP search"
                if self.selected_backend == "windows"
                else "LDAP search",
                "completed" if completed and failure is None else "failed",
                total if completed and failure is None else None,
                int((time.monotonic() - started) * 1000),
                failure
                if failure is not None
                else (None if completed else "LDAP read did not finish"),
            )
            self.last_query_result = result
            if self.on_query is not None:
                self.on_query(result)
            # Existing consumers do not opt into saved query outcomes.
            logger.verbose(
                "LDAP search complete: entries=%d pages=%d",
                total,
                page,
            )

    # Map wire-protocol (lowercased) attribute names to clean output keys.
    _ATTR_KEY_MAP: dict[str, str] = {
        "distinguishedname": "distinguishedName",
        "dnshostname": "dnsHostName",
        "samaccountname": "sAMAccountName",
        "userprincipalname": "userPrincipalName",
        "objectclass": "objectClass",
        "serviceprincipalname": "servicePrincipalName",
        "useraccountcontrol": "userAccountControl",
        "memberof": "memberOf",
        "name": "name",
    }

    @staticmethod
    def _entry_to_dict(entry) -> dict[str, Any]:
        """Convert an ldap3 Entry into a plain dict, decoding binary SIDs/GUIDs.

        Output keys use MSSQLHound's camelCase attribute names (D11: keep the
        original property names so BloodHound entity panels render them).
        """
        out: dict[str, Any] = {"distinguishedName": str(entry.entry_dn)}
        for attr_name in entry.entry_attributes:
            lower = attr_name.lower()
            raw = entry[attr_name].raw_values
            if lower == "objectsid":
                out["objectSid"] = bytes_to_sid(raw[0]) if raw else None
                continue
            if lower == "objectguid":
                out["objectGuid"] = bytes_to_guid(raw[0]) if raw else None
                continue
            out_key = AdClient._ATTR_KEY_MAP.get(lower, attr_name)
            if not raw:
                out[out_key] = None
                continue
            values = []
            for v in raw:
                if isinstance(v, (bytes, bytearray)):
                    try:
                        values.append(v.decode("utf-8", errors="replace"))
                    except Exception:
                        values.append(v.hex())
                else:
                    values.append(v)
            out[out_key] = values if len(values) > 1 else values[0]
        return out

    # --------------------------------------------------------- public queries --

    def enumerate_spns(self, spn_filter: str = "MSSQLSvc/*") -> list[dict[str, Any]]:
        """Paged ``(servicePrincipalName=<filter>)`` enumeration.

        Returns one dict per account with: ``servicePrincipalName`` (list),
        ``distinguishedName``, ``objectSid``, ``sAMAccountName``. Mirrors Go's
        ``EnumerateMSSQLSPNs`` (default filter ``MSSQLSvc/*``, page size 1000).
        """
        search_filter = f"(servicePrincipalName={spn_filter})"
        logger.info("Enumerating SPNs with filter %s", search_filter)
        results: list[dict[str, Any]] = []
        for entry in self.paged_search(
            search_filter=search_filter,
            attributes=[
                "servicePrincipalName",
                "sAMAccountName",
                "objectSid",
                "distinguishedName",
            ],
        ):
            spns = entry.get("servicePrincipalName")
            if spns is None:
                # Defensive: a match with no SPN value is unexpected; skip it.
                logger.debug(
                    "enumerate_spns: entry %s had no SPN values",
                    entry.get("distinguishedName"),
                )
                continue
            results.append(
                {
                    "servicePrincipalName": spns if isinstance(spns, list) else [spns],
                    "distinguishedName": entry.get("distinguishedName"),
                    "objectSid": entry.get("objectSid"),
                    "sAMAccountName": entry.get("sAMAccountName"),
                }
            )
        logger.info(
            "enumerate_spns: %d account(s) matched %s", len(results), search_filter
        )
        return results

    def enumerate_computers(self) -> list[dict[str, Any]]:
        """Paged ``(objectClass=computer)`` enumeration for scan-all-computers.

        Returns one dict per computer with ``dnsHostName``, ``name``,
        ``objectSid``, ``distinguishedName``. Mirrors Go's
        ``EnumerateAllComputers`` (which filters objectCategory+objectClass).
        """
        search_filter = "(&(objectCategory=computer)(objectClass=computer))"
        logger.info("Enumerating all computer objects")
        results: list[dict[str, Any]] = []
        for entry in self.paged_search(
            search_filter=search_filter,
            attributes=["dNSHostName", "name", "objectSid", "distinguishedName"],
        ):
            results.append(
                {
                    "dnsHostName": entry.get("dnsHostName"),
                    "name": entry.get("name"),
                    "objectSid": entry.get("objectSid"),
                    "distinguishedName": entry.get("distinguishedName"),
                }
            )
        logger.info("enumerate_computers: %d computer(s) found", len(results))
        return results

    def resolve_sid(self, sid: str) -> Optional[dict[str, Any]]:
        """Resolve a SID to a domain object, or None if not found.

        Returns ``{"name", "type", "samAccountName", "dnsHostName", "upn",
        "enabled", "dn", "sid"}``. ``type`` is one of user/group/computer (or
        the raw object class). Naming mirrors Go ``ResolveSID``: computers use
        dnsHostName, users use UPN, else ``DOMAIN\\sam``. Results are cached.
        """
        if sid in self._sid_cache:
            return self._sid_cache[sid]

        attrs = [
            "sAMAccountName",
            "distinguishedName",
            "objectClass",
            "userAccountControl",
            "dNSHostName",
            "userPrincipalName",
        ]

        # AD matches objectSid against the canonical S-1-... string form (the
        # SDDL syntax), which ldap3 passes through cleanly. Try that first.
        entry = self._first_entry(f"(objectSid={escape_filter_chars(sid)})", attrs)
        if entry is None:
            # Fallback: byte-escaped binary objectSid, for DCs/dirs that only
            # match the raw binary form. (Some ldap3 builds re-escape the
            # backslashes, so this is a best-effort second attempt.)
            binary = sid_to_ldap_filter_bytes(sid)
            if binary is not None:
                entry = self._first_entry(f"(objectSid={binary})", attrs)
        if entry is None:
            logger.debug("resolve_sid: SID %s not found", sid)
            self._sid_cache[sid] = None
            return None

        principal = self._build_principal(entry, sid=sid)
        self._sid_cache[sid] = principal
        return principal

    def resolve_principal(self, name: str) -> Optional[dict[str, Any]]:
        """Resolve a name (``DOMAIN\\user``, ``user@domain``, or bare sam) to a
        domain object (same dict shape as :meth:`resolve_sid`, incl. ``sid``).

        Mirrors Go ``ResolveName``: strips the domain qualifier and searches by
        sAMAccountName. Returns None if not found. Results are cached by name.
        """
        if name in self._name_cache:
            return self._name_cache[name]

        # Strip DOMAIN\ or @domain to get the bare account name.
        if "\\" in name:
            sam = name.split("\\", 1)[1]
        elif "@" in name:
            sam = name.split("@", 1)[0]
        else:
            sam = name

        entry = self._first_entry(
            f"(sAMAccountName={escape_filter_chars(sam)})",
            [
                "sAMAccountName",
                "distinguishedName",
                "objectClass",
                "objectSid",
                "userAccountControl",
                "dNSHostName",
                "userPrincipalName",
            ],
        )
        if entry is None:
            logger.debug("resolve_principal: name %s not found", name)
            self._name_cache[name] = None
            return None

        principal = self._build_principal(entry, sid=entry.get("objectSid"))
        self._name_cache[name] = principal
        # Also cache by SID so a later resolve_sid hits the cache.
        if principal.get("sid"):
            self._sid_cache[principal["sid"]] = principal
        return principal

    # ----------------------------------------------------------- query helpers --

    def _first_entry(
        self, search_filter: str, attributes: list[str]
    ) -> Optional[dict[str, Any]]:
        """Return the first matching entry dict, or None. size_limit=1."""
        # Consume the explicitly limited read so its outcome is finalized before
        # returning to the caller. There is no abandoned generator to clean up.
        entries = list(
            self.paged_search(
                search_filter=search_filter,
                attributes=attributes,
                size_limit=1,
                paged_size=1,
            )
        )
        return entries[0] if entries else None

    def _build_principal(
        self, entry: dict[str, Any], *, sid: Optional[str]
    ) -> dict[str, Any]:
        """Shape an LDAP entry dict into the resolve_* return contract."""
        sam = entry.get("sAMAccountName")
        dn = entry.get("distinguishedName")
        dns_host = entry.get("dnsHostName")
        upn = entry.get("userPrincipalName")

        # objectClass arrives as a list (e.g. top/person/user); pick the most
        # specific recognized class, matching Go's switch.
        classes = entry.get("objectClass")
        classes = (
            classes if isinstance(classes, list) else ([classes] if classes else [])
        )
        lowered = {str(c).lower() for c in classes}
        # Optional because the final fallback can find no class at all to report.
        obj_type: Optional[str]
        if "computer" in lowered:
            obj_type = "computer"
        elif "group" in lowered:
            obj_type = "group"
        elif "user" in lowered:
            obj_type = "user"
        else:
            # Fall back to the first raw class so the caller still gets a hint.
            obj_type = classes[0] if classes else None

        # Enabled: UAC flag 0x2 (ACCOUNTDISABLE). Absent UAC → treat as enabled.
        uac_raw = entry.get("userAccountControl")
        enabled = True
        # Spelled out rather than `not in (None, "")`: an identity/equality tuple test
        # tells a type checker nothing, so int() below still saw Any | None.
        if uac_raw is not None and uac_raw != "":
            try:
                enabled = not (int(uac_raw) & 0x2)
            except (TypeError, ValueError):
                # Non-numeric UAC — can't decide; default to enabled and log.
                logger.debug(
                    "_build_principal: non-numeric userAccountControl %r", uac_raw
                )

        # Name selection mirrors Go ResolveSID:
        #   computer → dnsHostName else DOMAIN\sam
        #   user     → userPrincipalName else DOMAIN\sam
        #   default  → DOMAIN\sam
        domain_sam = f"{self.domain}\\{sam}" if sam else None
        if obj_type == "computer" and dns_host:
            name = dns_host
        elif obj_type == "user" and upn:
            name = upn
        else:
            name = domain_sam

        return {
            "name": name,
            "type": obj_type,
            "samAccountName": sam,
            "dnsHostName": dns_host,
            "upn": upn,
            "enabled": enabled,
            "dn": dn,
            "sid": sid,
        }


__all__ = [
    "AdClient",
    "LdapAuth",
    "bytes_to_guid",
    "bytes_to_sid",
    "sid_to_ldap_filter_bytes",
]
