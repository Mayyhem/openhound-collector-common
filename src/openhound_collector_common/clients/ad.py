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
    into a private in-memory ccache that ldap3's SASL GSSAPI backend then uses.
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

import atexit
import base64
import importlib
import ipaddress
import os
import socket
import struct
import sys
import tempfile

from dataclasses import dataclass
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
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.core.results import RESULT_SUCCESS
from ldap3.utils.conv import escape_filter_chars

# Importing the shared logging module registers the VERBOSE level and the
# ``Logger.verbose`` method we use below (per-search trace). Imported for that
# side effect; ``noqa`` because the name itself is unused here.
from ..logging.log_context import get_logger

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
    if "invalidcredentials" not in text:
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
        struct.unpack("<I", value[8 + i * 4: 8 + i * 4 + 4])[0]
        for i in range(sub_authority_count)
    ]
    parts = [str(revision), str(identifier_authority)] + [str(sa) for sa in sub_authorities]
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
    * ``kerberos_ticket`` (base64 KRB-CRED) → GSSAPI bind via a private ccache.
    * none of the above → current-user SSPI (Windows) or anonymous.
    """

    username: Optional[str] = None
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    kerberos_ticket: Optional[str] = None  # base64 KRB-CRED (.kirbi)


@dataclass(frozen=True)
class _BindAttempt:
    """One (transport, hardening, bind-mode) tuple in the waterfall."""

    label: str
    use_ssl: bool
    port: int
    start_tls: bool
    session_security: bool  # NTLM sign+seal — requires NTLM credentials
    channel_binding: bool   # TLS CBT — requires TLS + NTLM credentials
    auth_mode: str          # "ntlm" | "ntlm_hash" | "kerberos" | "sspi_ntlm" | "anonymous"


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
    ) -> None:
        self.domain = domain
        self.dc = dc
        self.auth = auth or LdapAuth()
        self.port = port
        self.base_dn = ",".join(f"DC={part}" for part in domain.split(".")) if domain else ""
        self._conn: Optional[Connection] = None
        self._ccache_path: Optional[str] = None  # temp ccache for PtT, if used
        self._sid_cache: dict[str, Optional[dict[str, Any]]] = {}
        self._name_cache: dict[str, Optional[dict[str, Any]]] = {}

    # ------------------------------------------------------------------ bind --

    def bind(self) -> Connection:
        if self._conn is not None and self._conn.bound:
            return self._conn

        attempts = self._build_attempt_plan()
        attempts, host = self._prepare_attempts_and_host(attempts)
        self._log_credential_summary(attempts)

        last_exc: Optional[BaseException] = None
        for attempt in attempts:
            try:
                self._conn = self._open_connection(host=host, attempt=attempt)
                logger.info(
                    "LDAP connected: %s:%d (auth=%s, profile=%s)",
                    host, attempt.port, attempt.auth_mode, attempt.label,
                )
                return self._conn
            except LDAPException as exc:
                if _is_credential_failure(exc):
                    # Bad/locked/expired credential — stop now to avoid lockout.
                    logger.error("LDAP bind via %s failed with a credential error: %s", attempt.label, exc)
                    raise
                last_exc = exc
                logger.debug("LDAP bind via %s failed (%s); trying next profile", attempt.label, exc)
                continue
            except OSError as exc:
                # Connect/TLS failure — no auth attempted, safe to fall through.
                last_exc = exc
                logger.debug(
                    "LDAP transport to %s:%d (%s) failed: %s; trying next profile",
                    host, attempt.port, attempt.label, exc,
                )
                continue
            except Exception as exc:
                if attempt.auth_mode in ("kerberos", "sspi_ntlm"):
                    # Integrated-auth backends raise non-LDAP exceptions (SSPI /
                    # GSSAPI errors); treat as a soft failure and keep going.
                    last_exc = exc
                    logger.debug("LDAP bind via %s failed (%s); trying next profile", attempt.label, exc)
                    continue
                # Unexpected failure on an explicit-cred path — surface it.
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("LDAP connection failed before any bind was attempted")

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:
                # Unbind on an already-dead socket is noise; ignore.
                pass
            self._conn = None
        self._cleanup_ccache()

    # ------------------------------------------------------------- planning --

    def _has_explicit_ntlm(self) -> bool:
        return bool(self.auth.username and self.auth.password)

    def _has_nt_hash(self) -> bool:
        return bool(self.auth.username and self.auth.nt_hash)

    def _has_ticket(self) -> bool:
        return bool(self.auth.kerberos_ticket)

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
            return mode in ("ntlm", "ntlm_hash", "sspi_ntlm")

        def ldaps(mode: str, port: int) -> _BindAttempt:
            cbt = cbt_capable(mode)
            return _BindAttempt(
                label=f"LDAPS{'+CBT' if cbt else ''}", use_ssl=True, port=port,
                start_tls=False, session_security=False, channel_binding=cbt, auth_mode=mode,
            )

        def starttls(mode: str, port: int) -> _BindAttempt:
            cbt = cbt_capable(mode)
            return _BindAttempt(
                label=f"StartTLS{'+CBT' if cbt else ''}", use_ssl=False, port=port,
                start_tls=True, session_security=False, channel_binding=cbt, auth_mode=mode,
            )

        def ldap_signed(mode: str, port: int) -> _BindAttempt:
            return _BindAttempt(
                label="LDAP+sign/seal", use_ssl=False, port=port,
                start_tls=False, session_security=True, channel_binding=False, auth_mode=mode,
            )

        def ldap_plain(mode: str, port: int) -> _BindAttempt:
            return _BindAttempt(
                label="LDAP", use_ssl=False, port=port,
                start_tls=False, session_security=False, channel_binding=False, auth_mode=mode,
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
        if rdns_hostname:
            logger.info(
                "LDAP auth: reverse DNS resolved Kerberos DC IP '%s' to '%s'; "
                "using that hostname to build the LDAP service principal name.",
                self.dc, rdns_hostname,
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
            logger.info("LDAP auth: Kerberos pass-the-ticket (base64 KRB-CRED)")
        elif "kerberos" in modes:
            logger.info("LDAP auth: integrated Kerberos (current OS user TGT)")
        elif "sspi_ntlm" in modes:
            logger.info("LDAP auth: current-user NTLM via Windows SSPI")

    # ------------------------------------------------------- connection open --

    def _open_connection(self, *, host: str, attempt: _BindAttempt) -> Connection:
        """Open and bind one Connection with the requested security settings."""
        server = Server(host, port=attempt.port, use_ssl=attempt.use_ssl, get_info=ALL, connect_timeout=5)

        kwargs: dict[str, Any] = {
            "auto_bind": AUTO_BIND_TLS_BEFORE_BIND if attempt.start_tls else AUTO_BIND_NO_TLS,
            "read_only": True,
            "receive_timeout": 30,
            # Never chase referrals: a subtree search at the domain root makes AD
            # return continuation references to other partitions; ldap3 would
            # open new (unreachable) connections to follow them. We only want
            # this DC's own data.
            "auto_referrals": False,
        }

        if attempt.auth_mode == "sspi_ntlm":
            return self._open_current_user_ntlm_connection(server=server, attempt=attempt)

        if attempt.auth_mode in ("ntlm", "ntlm_hash"):
            kwargs.update({
                "user": self._ntlm_user(),
                "password": self._ntlm_secret(attempt.auth_mode),
                "authentication": NTLM,
            })
        elif attempt.auth_mode == "kerberos":
            # GSSAPI reads the principal from the OS cred cache. For pass-the-
            # ticket we point KRB5CCNAME at a private ccache built from the
            # base64 KRB-CRED before the bind (see _ensure_ticket_ccache).
            self._ensure_ticket_ccache()
            kwargs.update({"authentication": SASL, "sasl_mechanism": KERBEROS})
        # "anonymous" → leave authentication unset (ldap3 default ANONYMOUS).

        if attempt.session_security:
            kwargs["session_security"] = ENCRYPT
        if attempt.channel_binding and attempt.auth_mode in ("ntlm", "ntlm_hash"):
            kwargs["channel_binding"] = TLS_CHANNEL_BINDING

        try:
            return Connection(server, **kwargs)
        except TypeError as exc:
            # Older ldap3 rejects session_security / channel_binding kwargs.
            if attempt.session_security or attempt.channel_binding:
                raise RuntimeError(
                    "LDAP signing / channel binding requires ldap3 >= 2.10.2rc4 "
                    "(session_security and channel_binding support)."
                ) from exc
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

    def _open_current_user_ntlm_connection(self, *, server: Server, attempt: _BindAttempt) -> Connection:
        conn = Connection(
            server, auto_bind=AUTO_BIND_NONE, authentication=NTLM, read_only=True,
            receive_timeout=30, auto_referrals=False,
            # session_security likewise postdates the 2.9.13 stubs (see the ENCRYPT import).
            session_security=ENCRYPT if attempt.session_security else None,  # type: ignore[call-arg]
        )
        conn.open(read_server_info=False)
        if attempt.start_tls and not conn.start_tls(read_server_info=False):
            error = "StartTLS before current-user NTLM bind failed"
            if conn.last_error:
                error = f"{error}: {conn.last_error}"
            conn.unbind()
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

                request = bind_operation(conn.version, "SICILY_PACKAGE_DISCOVERY", ntlm_client)
                response = conn.post_send_single_response(conn.send("bindRequest", request, controls))
                result = response[0] if conn.strategy.sync else conn.get_response(response)[1]
                packages = (result.get("server_creds") or b"").decode("ascii", errors="ignore").split(";")
                if "NTLM" not in packages:
                    raise LDAPBindError("DC did not advertise the NTLM Sicily package")

                request = bind_operation(conn.version, "SICILY_NEGOTIATE_NTLM", ntlm_client)
                response = conn.post_send_single_response(conn.send("bindRequest", request, controls))
                result = response[0] if conn.strategy.sync else conn.get_response(response)[1]

                if result and result.get("result") == RESULT_SUCCESS:
                    request = bind_operation(
                        conn.version, "SICILY_RESPONSE_NTLM", ntlm_client, result.get("server_creds"),
                    )
                    response = conn.post_send_single_response(conn.send("bindRequest", request, controls))
                    result = response[0] if conn.strategy.sync else conn.get_response(response)[1]

                conn.result = result
                conn.bound = bool(result and result.get("result") == RESULT_SUCCESS)
                if not conn.bound:
                    description = result.get("description") if result else None
                    message = result.get("message") if result else None
                    conn.last_error = description or message or "current-user NTLM bind failed"
                    raise LDAPBindError(conn.last_error)
            except LDAPException:
                raise
            except Exception as ex:
                raise LDAPBindError(f"current-user NTLM via Windows SSPI failed: {ex}") from ex
            finally:
                conn.sasl_in_progress = False

    # ----------------------------------------------------- ticket → ccache --

    def _ensure_ticket_ccache(self) -> None:
        """Load the base64 KRB-CRED into a private ccache and point KRB5CCNAME
        at it so ldap3's SASL GSSAPI backend authenticates with that ticket.

        Cross-platform pass-the-ticket: impacket parses the ``.kirbi`` blob,
        writes a temp ccache, and the OS Kerberos backend (gssapi/winkerberos)
        reads it via KRB5CCNAME. Cleaned up on close() and at interpreter exit.
        """
        if self._ccache_path is not None:
            # Already materialized for this client — reuse it.
            return
        ticket = self.auth.kerberos_ticket
        if not ticket:
            # No ticket configured — nothing to do (shouldn't happen on this path).
            return
        try:
            from impacket.krb5.ccache import CCache
        except ImportError as exc:
            raise RuntimeError("Kerberos pass-the-ticket requires impacket (CCache).") from exc
        try:
            ccache = CCache()
            ccache.fromKRBCRED(base64.b64decode(ticket, validate=True))
        except Exception as exc:
            raise ValueError(f"--ldap-ticket is not a valid base64 KRB-CRED (.kirbi): {exc}") from exc

        fd, path = tempfile.mkstemp(prefix="oh_ldap_", suffix=".ccache")
        os.close(fd)
        ccache.saveFile(path)
        os.environ["KRB5CCNAME"] = path
        self._ccache_path = path
        # Ensure the temp ccache is removed even if close() isn't called.
        atexit.register(self._cleanup_ccache)
        logger.debug("Loaded pass-the-ticket KRB-CRED into ccache %s", path)

    def _cleanup_ccache(self) -> None:
        if self._ccache_path is None:
            return
        try:
            os.unlink(self._ccache_path)
        except OSError as exc:
            # Best-effort cleanup; a leftover temp ccache is harmless.
            logger.debug("Could not remove temp ccache %s: %s", self._ccache_path, exc)
        finally:
            self._ccache_path = None

    # ---------------------------------------------------------- paged search --

    def paged_search(
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
    ) -> Iterable[dict[str, Any]]:
        """Yield each matching entry as a dict {attr: value}, decoding SIDs/GUIDs.

        Paged at *paged_size* (1000, matching the Go controls + AD's default
        cap). A server-side error (e.g. ``noSuchObject``) is logged and stops
        iteration rather than raising into the caller's generator.
        """
        conn = self.bind()
        base_dn = base or self.base_dn
        logger.verbose("LDAP search: base=%s filter=%s", base_dn, search_filter)
        total = 0
        page = 0
        try:
            cookie = None
            while True:
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
                result = conn.result or {}
                desc = result.get("description")
                if desc and desc.lower() not in ("success", "sizelimitexceeded"):
                    # Server reported an error without raising — surface it.
                    logger.warning(
                        "LDAP search returned %s (base=%s filter=%s): %s",
                        desc, base_dn, search_filter, result.get("message") or "",
                    )
                    break
                page += 1
                total += len(conn.entries)
                for entry in conn.entries:
                    yield self._entry_to_dict(entry)
                cookie = (
                    result.get("controls", {})
                    .get("1.2.840.113556.1.4.319", {})
                    .get("value", {})
                    .get("cookie")
                )
                if not cookie:
                    # No continuation cookie — last page consumed.
                    break
        except LDAPException as exc:
            logger.warning("LDAP search failed (filter=%s, base=%s): %s", search_filter, base_dn, exc)
        finally:
            logger.verbose(
                "LDAP search complete: entries=%d pages=%d", total, page,)

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
            attributes=["servicePrincipalName", "sAMAccountName", "objectSid", "distinguishedName"],
        ):
            spns = entry.get("servicePrincipalName")
            if spns is None:
                # Defensive: a match with no SPN value is unexpected; skip it.
                logger.debug("enumerate_spns: entry %s had no SPN values", entry.get("distinguishedName"))
                continue
            results.append({
                "servicePrincipalName": spns if isinstance(spns, list) else [spns],
                "distinguishedName": entry.get("distinguishedName"),
                "objectSid": entry.get("objectSid"),
                "sAMAccountName": entry.get("sAMAccountName"),
            })
        logger.info("enumerate_spns: %d account(s) matched %s", len(results), search_filter)
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
            results.append({
                "dnsHostName": entry.get("dnsHostName"),
                "name": entry.get("name"),
                "objectSid": entry.get("objectSid"),
                "distinguishedName": entry.get("distinguishedName"),
            })
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

        attrs = ["sAMAccountName", "distinguishedName", "objectClass",
                 "userAccountControl", "dNSHostName", "userPrincipalName"]

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
            ["sAMAccountName", "distinguishedName", "objectClass", "objectSid",
             "userAccountControl", "dNSHostName", "userPrincipalName"],
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

    def _first_entry(self, search_filter: str, attributes: list[str]) -> Optional[dict[str, Any]]:
        """Return the first matching entry dict, or None. size_limit=1."""
        for entry in self.paged_search(search_filter=search_filter, attributes=attributes, size_limit=1, paged_size=1):
            return entry
        return None

    def _build_principal(self, entry: dict[str, Any], *, sid: Optional[str]) -> dict[str, Any]:
        """Shape an LDAP entry dict into the resolve_* return contract."""
        sam = entry.get("sAMAccountName")
        dn = entry.get("distinguishedName")
        dns_host = entry.get("dnsHostName")
        upn = entry.get("userPrincipalName")

        # objectClass arrives as a list (e.g. top/person/user); pick the most
        # specific recognized class, matching Go's switch.
        classes = entry.get("objectClass")
        classes = classes if isinstance(classes, list) else ([classes] if classes else [])
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
            obj_type = (classes[0] if classes else None)

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
                logger.debug("_build_principal: non-numeric userAccountControl %r", uac_raw)

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
