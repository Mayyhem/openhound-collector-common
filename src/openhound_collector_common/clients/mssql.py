# Generalized from sccm/sccm/src/openhound_sccm/clients/mssql_epa.py.
#
# "Generalize" per design spec §2.1 / §9 / §3:
#   - The SCCM file did EPA *detection only* (it never opened a usable query
#     connection). This module keeps the proven EPA probe matrix + decision tree
#     and ADDS the real connection-strategy waterfall + query path the MSSQL
#     collector needs (ported from MSSQLHound's Go connectNative/IsAuthError in
#     MSSQLHound/internal/mssql/client.go).
#   - Auth inputs are collapsed into one `Auth` dataclass (per design D12: a
#     single base64 KRB-CRED `kerberos_ticket` replaces the five Go krb5 flags).
#   - SCCM-specific orchestration (`test_epa` auth ladder reading a SourceContext,
#     SPN-list plumbing) is dropped; callers pass an `Auth` + target string.
#
# CRITICAL (design §3 / §14): impacket's TDS 7.x `set_tls_context()` sets only the
# TLS *minimum* version, NOT the maximum, so a TLS 1.3-capable server+client would
# negotiate 1.3 and lose `tls-unique` (RFC 8446 removed it), breaking EPA channel
# binding. impacket's TDS 8.0 `_setup_tds8()` already caps at 1.2. We subclass
# `tds.MSSQL` and override `set_tls_context` to cap the context at TLS 1.2 on the
# 7.x path too, matching the Go client which sets MaxVersion=TLS12 on every path.
#
# A log line accompanies each if/else and try/except per the project rule, except
# where a one-line comment already explains a trivial branch.
"""Pure-Python, in-process TDS/auth client + EPA detection for SQL Server.

Two public surfaces:

* :class:`MssqlConnection` — open a real authenticated TDS connection and run
  queries. ``connect(target, auth)`` walks the connection-strategy waterfall
  (encrypt / TDS-8 strict / no-encrypt; FQDN + short hostname; reverse-DNS cert
  name for IP targets) and **stops on an authentication error** so a bad
  credential never fans out into repeated logins (AD lockout safety), mirroring
  Go ``connectNative``/``IsAuthError``. ``query(sql)`` returns a list of row
  dicts. Usable as a context manager.

* :func:`detect_epa` — determine Extended Protection for Authentication (EPA)
  enforcement by running the five NTLM login probes (normal / bogus-CBT /
  missing-CBT / bogus-service / missing-service) and classifying the responses,
  per MSSQLHound's ``TestEPA``.

Auth is described by the :class:`Auth` dataclass (SQL login, domain NTLMv2 + EPA
channel binding, pass-the-hash, pass-the-ticket, current-user SSPI).

All TLS paths are forced to TLS 1.2 max so the EPA ``tls-unique`` channel binding
remains available.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Optional

from impacket import ntlm, tds

from . import auth as auth_mod
from ..logging.log_context import get_logger

logger = get_logger(__name__)

# MS-TDS PRELOGIN encryption byte values (mirror impacket.tds.TDS_ENCRYPT_*).
ENCRYPT_OFF = tds.TDS_ENCRYPT_OFF        # 0
ENCRYPT_ON = tds.TDS_ENCRYPT_ON          # 1
ENCRYPT_NOT_SUP = tds.TDS_ENCRYPT_NOT_SUP  # 2
ENCRYPT_REQ = tds.TDS_ENCRYPT_REQ        # 3
ENCRYPT_STRICT = tds.TDS_ENCRYPT_STRICT  # 8

DEFAULT_PORT = 1433
DEFAULT_SERVICE_CLASS = "MSSQLSvc"

# A fixed 16-byte garbage channel binding token. A server enforcing channel
# binding rejects it; one that ignores bindings accepts it. Same bytes as the
# SCCM source / MSSQLHound for cross-tool consistency.
BOGUS_CBT = b"\xc0\x91\x30\xd2\xc4\xc3\xd4\xc7\x51\x5a\xb4\x52\xdf\x08\xaf\xfd"

# 16 bytes of garbage tls-unique material to forge a wrong SEC_CHANNEL_BINDINGS
# under SSPI (so Windows emits a channel-binding hash the server will reject).
_BOGUS_TLS_UNIQUE = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"

# Server-error substrings used to classify probe and connect outcomes.
_UNTRUSTED_DOMAIN_TEXT = "the login is from an untrusted domain"
_LOGIN_FAILED_TEXT = "login failed for"

# Auth-error substrings (mirror Go IsAuthError): these count toward AD lockout,
# so the connection waterfall must STOP rather than retry other strategies.
_AUTH_ERROR_TEXTS = (
    "login failed",
    "untrusted domain",
    "cannot be used with windows authentication",
    "cannot be used with integrated authentication",
    "no user credentials available",
    "password did not match",
)


# ---------------------------------------------------------------------------
# Auth description
# ---------------------------------------------------------------------------
@dataclass
class Auth:
    """How to authenticate to SQL Server (or for EPA probing).

    Exactly one credential family should be populated; the connection/probe code
    picks the auth mode from whichever fields are set:

      * SQL login: ``username`` + ``password`` (no ``domain``).
      * Domain NTLMv2 (+EPA channel binding — the main path): ``username`` +
        ``password`` + ``domain``.
      * Pass-the-hash: ``username`` + ``nt_hash`` + ``domain``.
      * Pass-the-ticket: ``kerberos_ticket`` (base64 ``.kirbi``/KRB-CRED), Kerberos
        only (no NTLM fallback), with ``username``/``domain`` for the principal.
      * Current-user SSPI (Windows SSO): ``use_sspi=True``, no other creds.

    ``spn`` optionally pins the service principal name (e.g. a registered
    ``MSSQLSvc/host.fqdn:1433``); when unset it is derived as
    ``MSSQLSvc/<host>:<port>``.
    """

    username: Optional[str] = None
    password: Optional[str] = None
    nt_hash: Optional[str] = None          # pass-the-hash (bare NT or LM:NT)
    kerberos_ticket: Optional[str] = None  # pass-the-ticket: base64 KRB-CRED
    use_sspi: bool = False                 # current-user SSPI (Windows)
    domain: str = ""
    spn: Optional[str] = None              # explicit SPN override
    kdc_host: Optional[str] = None         # KDC for fetching a service ticket

    def is_windows_auth(self) -> bool:
        """True when this is Windows auth (domain NTLM, PtH, PtT, or SSPI)."""
        # A non-empty domain, an NT hash, a Kerberos ticket, or SSPI all imply
        # integrated/Windows auth; bare username+password is a SQL login.
        return bool(self.domain or self.nt_hash or self.kerberos_ticket or self.use_sspi)

    def is_sql_login(self) -> bool:
        """True for a plain SQL login (username+password, no Windows auth)."""
        return bool(self.username and self.password) and not self.is_windows_auth()


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------
@dataclass
class Target:
    """Parsed connection target: host (+optional instance/port)."""

    host: str
    port: int = DEFAULT_PORT
    instance: Optional[str] = None


def parse_target(target: str) -> Target:
    """Parse ``host`` / ``host:port`` / ``host\\instance`` / SPN into a Target.

    Mirrors Go ``parseServerInstance``: an ``MSSQLSvc/`` SPN prefix is stripped,
    ``host\\instance`` keeps the instance (port left at default — SQL Browser
    resolution is out of scope here), and ``host:port`` overrides the port.
    """
    spec = target.strip()
    if spec.upper().startswith("MSSQLSVC/"):
        # SPN form MSSQLSvc/host:port — drop the service-class prefix.
        spec = spec[len("MSSQLSVC/"):]
    if "\\" in spec:
        # host\instance (optionally with :port on the instance).
        host, rest = spec.split("\\", 1)
        if ":" in rest:
            instance, port_str = rest.rsplit(":", 1)
            return Target(host=host, port=_to_port(port_str), instance=instance)
        return Target(host=host, instance=rest)
    if ":" in spec:
        # host:port.
        host, port_str = spec.rsplit(":", 1)
        return Target(host=host, port=_to_port(port_str))
    # Bare hostname.
    return Target(host=spec)


def _to_port(text: str) -> int:
    """Parse a port string, falling back to the default on garbage."""
    try:
        return int(text)
    except ValueError:
        logger.warning("Invalid port %r in target; using default %d", text, DEFAULT_PORT)
        return DEFAULT_PORT


def default_spn(host: str, port: int) -> str:
    """Derive the conventional ``MSSQLSvc/host:port`` SPN."""
    return f"{DEFAULT_SERVICE_CLASS}/{host}:{port}"


def is_auth_error(message: str) -> bool:
    """True when *message* is a credential failure (counts toward lockout)."""
    lowered = message.lower()
    return any(text in lowered for text in _AUTH_ERROR_TEXTS)


def _nulls_to_none(row: dict) -> dict:
    """Map impacket's literal ``"NULL"`` SQL-NULL marker to Python ``None``.

    impacket's row decoder returns the *string* ``"NULL"`` for a SQL NULL in
    every column branch (``tds.MSSQL.parseRow``). We translate that marker to
    ``None`` so a NULL serializes to JSON ``null`` rather than the string
    ``"NULL"``. This is a known, unavoidable ambiguity: a genuine character
    value of exactly ``"NULL"`` is rare and not worth a per-type decode rewrite;
    callers needing that distinction should compare against ``None``.
    """
    return {key: (None if value == "NULL" else value) for key, value in row.items()}


# ---------------------------------------------------------------------------
# TLS-1.2-capped TDS client
# ---------------------------------------------------------------------------
class _Tds(tds.MSSQL):
    """impacket TDS client with the EPA-critical TLS 1.2 cap on the 7.x path.

    impacket's TDS 8.0 ``_setup_tds8`` already caps at TLS 1.2; its TDS 7.x
    ``set_tls_context`` does not. We override the 7.x path to cap the SSL context
    so ``tls-unique`` (needed for EPA channel binding) stays available. We also
    expose the EPA-relevant encryption flag / strict status and a controllable
    EPA login (channel-binding token, service SPN class, target-name AV pair).
    """

    #: PRELOGIN encryption flag observed during the last login.
    epa_encryption_flag: int = ENCRYPT_OFF
    #: Whether the last login used TDS 8.0 strict encryption.
    epa_is_strict: bool = False

    def set_tls_context(self):
        """Set up the TDS 7.x TLS-over-TDS tunnel, capping the context at TLS 1.2.

        This reimplements impacket 0.13.x's ``tds.MSSQL.set_tls_context`` verbatim
        EXCEPT it adds ``context.maximum_version = TLSv1_2``. impacket's own 7.x
        method sets only ``minimum_version`` and never exposes its context, so we
        cannot cap it from the outside (and the cap must be applied before the
        handshake). Reimplementing the ~20-line STARTTLS-style handshake is far
        cleaner than monkeypatching ``ssl.SSLContext`` (whose property setters
        resolve the class by global name and break under any swap).

        The TLS 1.2 cap is EPA-critical: TLS 1.3 removed ``tls-unique`` (RFC 8446)
        and SQL Server's SChannel does not accept ``tls-server-end-point`` as a
        substitute, so channel binding would be impossible over a 1.3 session.
        """
        logger.debug("TDS 7.x: negotiating TLS-over-TDS (capped at TLS 1.2)")
        context = ssl.SSLContext()
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        # The EPA-critical cap (the one line impacket's 7.x path omits).
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # MSSQL expects TLS records wrapped in TDS PRELOGIN packets, so drive the
        # handshake through MemoryBIOs and shuttle bytes inside TDS frames.
        in_bio = ssl.MemoryBIO()
        out_bio = ssl.MemoryBIO()
        tls = context.wrap_bio(in_bio, out_bio)
        while True:
            try:
                tls.do_handshake()
            except ssl.SSLWantReadError:
                # Server wants our pending bytes, then sends its own — exchange
                # them inside TDS PRELOGIN packets until the handshake completes.
                self.sendTDS(tds.TDS_PRE_LOGIN, out_bio.read(4096), 0)
                in_bio.write(self.recvTDS(4096)["Data"])
            else:
                # Handshake finished.
                break

        self.packetSize = 16 * 1024 - 1
        self.tlsSocket = tls
        self.in_bio = in_bio
        self.out_bio = out_bio
        # tls-unique is the EPA channel-binding token; capture it now.
        self.tls_unique = tls.get_channel_binding("tls-unique")
        logger.debug("TDS 7.x TLS established (tls_unique=%s)",
                     "present" if self.tls_unique else "absent")

    def parseRow(self, token, tuplemode=False):
        """Decode one result row, fixing impacket's ``tinyint``/``bit`` handling.

        impacket's ``tds.MSSQL.parseRow`` decodes BOTH ``tinyint``
        (``TDS_INT1TYPE`` = 0x30) and ``bit`` (``TDS_BITTYPE`` = 0x32) with the
        single branch ``value = bool(data[0])``. That is wrong for ``tinyint``: a
        ``compatibility_level`` of 160 comes back as ``True`` (and 0 as
        ``False``), losing the integer outright; and it is lossy for ``bit``
        (a 0/1 flag becomes a Python ``bool`` that serializes as ``true``/``false``
        rather than ``0``/``1``).

        Because ``bool(160)`` has already discarded the value, the fix must land
        at decode time, and impacket exposes no hook narrower than ``parseRow``
        (one monolithic pass that consumes ``data`` sequentially). So — exactly
        as :meth:`set_tls_context` reimplements impacket's STARTTLS handshake to
        add a single missing line — we reproduce impacket 0.13.x's ``parseRow``
        VERBATIM and change only the ``TDS_BITTYPE``/``TDS_INT1TYPE`` branch to
        decode the raw byte as an unsigned integer (``data[0]``: 0/1 for ``bit``,
        0-255 for ``tinyint``). Every other branch is byte-for-byte identical to
        impacket so column byte-alignment is preserved. If impacket adds a data
        type we don't know, the trailing ``else`` raises exactly as upstream does
        — a loud, visible signal to refresh this copy.
        """
        # --- verbatim impacket parseRow, with the one corrected branch ---------
        import binascii
        import datetime
        import struct
        import uuid
        from decimal import Decimal, getcontext

        from impacket.tds import TDS_SSVARIANT

        if len(token) == 1:
            return 0

        row = [] if tuplemode else {}

        # Track how many bytes this row consumes. impacket's caller
        # (`_parse_reply_tokens`) truncates ``token["Data"]`` to this returned
        # length so the *next* token starts at the right offset; without the
        # return value it slices ``[:None]`` (the whole remaining buffer) and the
        # loop swallows every following row + the DONE token as one giant ROW,
        # yielding exactly one row per result set. So we MUST return the consumed
        # length, exactly as upstream impacket does.
        origDataLen = len(token["Data"])
        data = token["Data"]
        for col in self.colMeta:
            _type = col["Type"]
            if (_type == tds.TDS_NVARCHARTYPE) | (_type == tds.TDS_NCHARTYPE):
                charLen = struct.unpack("<H", data[: struct.calcsize("<H")])[0]
                data = data[struct.calcsize("<H") :]
                if charLen != 0xFFFF:
                    value = data[:charLen].decode("utf-16le")
                    data = data[charLen:]
                else:
                    value = "NULL"
            elif _type == tds.TDS_BIGVARCHRTYPE:
                charLen = struct.unpack("<H", data[:2])[0]
                data = data[2:]
                if charLen != 0xFFFF:
                    raw = data[:charLen]
                    data = data[charLen:]
                    try:
                        value = raw.decode("latin-1")
                    except UnicodeDecodeError:
                        value = raw.decode("utf-8", errors="replace")
                else:
                    value = "NULL"
            elif _type == tds.TDS_GUIDTYPE:
                uuidLen = ord(data[0:1])
                data = data[1:]
                if uuidLen > 0:
                    uu = data[:uuidLen]
                    value = uuid.bin_to_string(uu)
                    data = data[uuidLen:]
                else:
                    value = "NULL"
            elif (_type == tds.TDS_NTEXTTYPE) | (_type == tds.TDS_IMAGETYPE):
                charLen = ord(data[0:1])
                if charLen == 0:
                    value = "NULL"
                    data = data[1:]
                else:
                    data = data[1 + charLen + 8 :]
                    charLen = struct.unpack("<L", data[: struct.calcsize("<L")])[0]
                    data = data[struct.calcsize("<L") :]
                    if charLen != 0xFFFF:
                        if _type == tds.TDS_NTEXTTYPE:
                            value = data[:charLen].decode("utf-16le")
                        else:
                            value = binascii.b2a_hex(data[:charLen])
                        data = data[charLen:]
                    else:
                        value = "NULL"
            elif _type == tds.TDS_TEXTTYPE:
                charLen = ord(data[0:1])
                if charLen == 0:
                    value = "NULL"
                    data = data[1:]
                else:
                    data = data[1 + charLen + 8 :]
                    charLen = struct.unpack("<L", data[: struct.calcsize("<L")])[0]
                    data = data[struct.calcsize("<L") :]
                    if charLen != 0xFFFF:
                        value = data[:charLen]
                        data = data[charLen:]
                    else:
                        value = "NULL"
            elif (_type == tds.TDS_BIGVARBINTYPE) | (_type == tds.TDS_BIGBINARYTYPE):
                charLen = struct.unpack("<H", data[: struct.calcsize("<H")])[0]
                data = data[struct.calcsize("<H") :]
                if charLen != 0xFFFF:
                    value = binascii.b2a_hex(data[:charLen])
                    data = data[charLen:]
                else:
                    value = "NULL"
            elif (
                (_type == tds.TDS_DATETIM4TYPE)
                | (_type == tds.TDS_DATETIMNTYPE)
                | (_type == tds.TDS_DATETIMETYPE)
            ):
                value = ""
                if _type == tds.TDS_DATETIMNTYPE:
                    if ord(data[0:1]) == 4:
                        _type = tds.TDS_DATETIM4TYPE
                    elif ord(data[0:1]) == 8:
                        _type = tds.TDS_DATETIMETYPE
                    else:
                        value = "NULL"
                    data = data[1:]
                if _type == tds.TDS_DATETIMETYPE:
                    dateValue = struct.unpack("<l", data[:4])[0]
                    data = data[4:]
                    if dateValue < 0:
                        baseDate = datetime.date(1753, 1, 1)
                    else:
                        baseDate = datetime.date(1900, 1, 1)
                    timeValue = struct.unpack("<L", data[:4])[0]
                    data = data[4:]
                elif _type == tds.TDS_DATETIM4TYPE:
                    dateValue = struct.unpack("<H", data[: struct.calcsize("<H")])[0]
                    data = data[struct.calcsize("<H") :]
                    timeValue = struct.unpack("<H", data[: struct.calcsize("<H")])[0]
                    data = data[struct.calcsize("<H") :]
                    baseDate = datetime.date(1900, 1, 1)
                if value != "NULL":
                    dateValue = datetime.date.fromordinal(baseDate.toordinal() + dateValue)
                    hours, mod = divmod(timeValue // 300, 60 * 60)
                    minutes, second = divmod(mod, 60)
                    value = datetime.datetime(
                        dateValue.year, dateValue.month, dateValue.day,
                        hours, minutes, second,
                    )
            elif _type == tds.TDS_INT4TYPE:
                value = struct.unpack("<l", data[:4])[0]
                data = data[4:]
            elif _type == tds.TDS_FLT4TYPE:
                value = struct.unpack("<f", data[:4])[0]
                data = data[4:]
            elif _type == tds.TDS_MONEY4TYPE:
                raw = struct.unpack("<l", data[:4])[0]
                value = Decimal(raw) / Decimal(10000)
                data = data[4:]
            elif _type == tds.TDS_FLTNTYPE:
                valueSize = ord(data[:1])
                if valueSize == 4:
                    fmt = "<f"
                elif valueSize == 8:
                    fmt = "<d"
                data = data[1:]
                if valueSize > 0:
                    value = struct.unpack(fmt, data[:valueSize])[0]
                    data = data[valueSize:]
                else:
                    value = "NULL"
            elif _type == tds.TDS_MONEYNTYPE:
                valueSize = ord(data[:1])
                if valueSize == 4:
                    fmt = "<l"
                elif valueSize == 8:
                    fmt = "<q"
                data = data[1:]
                if valueSize > 0:
                    raw = struct.unpack("<q" if valueSize == 8 else "<l", data[:valueSize])[0]
                    value = Decimal(raw) / Decimal(10000)
                    data = data[valueSize:]
                else:
                    value = "NULL"
            elif _type == tds.TDS_BIGCHARTYPE:
                charLen = struct.unpack("<H", data[: struct.calcsize("<H")])[0]
                data = data[struct.calcsize("<H") :]
                value = data[:charLen]
                data = data[charLen:]
            elif _type == tds.TDS_INT8TYPE:
                value = struct.unpack("<q", data[:8])[0]
                data = data[8:]
            elif _type == tds.TDS_FLT8TYPE:
                value = struct.unpack("<d", data[:8])[0]
                data = data[8:]
            elif _type == tds.TDS_MONEYTYPE:
                high, low = struct.unpack("<lL", data[:8])
                combined = (high << 32) + low
                value = Decimal(combined) / Decimal(10000)
                data = data[8:]
            elif _type == tds.TDS_INT2TYPE:
                value = struct.unpack("<H", (data[:2]))[0]
                data = data[2:]
            elif _type == tds.TDS_DATENTYPE:
                valueSize = ord(data[:1])
                data = data[1:]
                if valueSize > 0:
                    dateBytes = data[:valueSize]
                    dateValue = struct.unpack("<L", dateBytes + b"\x00")[0]
                    value = datetime.date.fromordinal(dateValue)
                    data = data[valueSize:]
                else:
                    value = "NULL"
            elif (_type == tds.TDS_BITTYPE) | (_type == tds.TDS_INT1TYPE):
                # THE FIX: impacket does ``value = bool(data[0])`` here, collapsing
                # both bit and tinyint to a bool. Decode the raw byte as an
                # unsigned int instead — 0/1 for ``bit``, 0-255 for ``tinyint``
                # (so e.g. ``compatibility_level`` is 160, not ``True``).
                value = data[0]
                data = data[1:]
            elif _type in (tds.TDS_NUMERICNTYPE, tds.TDS_DECIMALNTYPE):
                valueLen = data[0]
                data = data[1:]
                if valueLen == 0:
                    value = "NULL"
                else:
                    raw = data[:valueLen]
                    data = data[valueLen:]
                    precision = col["TypeData"][1]
                    scale = col["TypeData"][2]
                    sign = 1 if raw[0] == 1 else -1
                    integer = int.from_bytes(raw[1:], byteorder="little", signed=False)
                    getcontext().prec = precision
                    number = Decimal(integer)
                    if scale:
                        number /= Decimal(10) ** scale
                    value = number if sign > 0 else -number
            elif _type == tds.TDS_BITNTYPE:
                valueSize = ord(data[:1])
                data = data[1:]
                if valueSize > 0:
                    if valueSize == 1:
                        value = ord(data[:valueSize])
                    else:
                        value = data[:valueSize]
                else:
                    value = "NULL"
                data = data[valueSize:]
            elif _type == tds.TDS_INTNTYPE:
                valueSize = ord(data[:1])
                if valueSize == 1:
                    fmt = "<B"
                elif valueSize == 2:
                    fmt = "<h"
                elif valueSize == 4:
                    fmt = "<l"
                elif valueSize == 8:
                    fmt = "<q"
                else:
                    fmt = ""
                data = data[1:]
                if valueSize > 0:
                    value = struct.unpack(fmt, data[:valueSize])[0]
                    data = data[valueSize:]
                else:
                    value = "NULL"
            elif _type == tds.TDS_SSVARIANTTYPE:
                totalLength = struct.unpack("<L", data[:4])[0]
                variantData = data[: 4 + totalLength]
                variant = TDS_SSVARIANT(variantData)
                value = variant.parse()
                data = data[4 + totalLength :]
            else:
                raise Exception("ParseROW: Unsupported data type: 0%x" % _type)

            if tuplemode:
                row.append(value)
            else:
                row[col["Name"]] = value

        self.rows.append(row)
        # Return the number of bytes consumed so `_parse_reply_tokens` advances
        # to the next token correctly (see the origDataLen note above). Upstream
        # impacket returns this same value.
        return origDataLen - len(data)

    def get_error_messages(self) -> str:
        """Join all TDS error tokens from the last reply into one string."""
        if not self.replies:
            # No reply parsed yet — nothing to report.
            return ""
        messages = []
        for token_list in self.replies.values():
            for token in token_list:
                if token["TokenType"] == tds.TDS_ERROR_TOKEN:
                    messages.append(
                        "(%s) %s"
                        % (
                            token["ServerName"].decode("utf-16le"),
                            token["MsgText"].decode("utf-16le"),
                        )
                    )
        return " ".join(messages)

    # -- EPA-controllable NTLM login (explicit credentials / PtH) ------------
    def login_epa(
        self,
        *,
        database,
        username,
        password="",
        domain="",
        nt_hash: Optional[str] = None,
        cbt_value: Optional[bytes] = None,
        service: str = DEFAULT_SERVICE_CLASS,
        strip_target_service: bool = False,
    ) -> bool:
        """Windows-auth login with the EPA bindings under our control.

        ``cbt_value``: None -> correct token from the TLS channel (empty when
        unencrypted); ``BOGUS_CBT`` -> wrong token; ``b""`` -> omit the channel
        binding AV pair. ``service`` is the SPN class for the target-name AV pair.
        ``strip_target_service`` omits the target-name AV pair entirely.
        """
        resp = self._negotiate_encryption()
        self.epa_is_strict = bool(self.tds8)
        self.epa_encryption_flag = ENCRYPT_STRICT if self.tds8 else resp["Encryption"]

        version = ntlm.VERSION()
        (version["ProductMajorVersion"], version["ProductMinorVersion"],
         version["ProductBuild"]) = (10, 0, 20348)

        type1 = auth_mod.ntlm_type1(version=version)
        login = self._build_login7(database, sspi=type1.getData())
        self.sendTDS(tds.TDS_LOGIN7, login.getData())
        # ENCRYPT_OFF: only the LOGIN7 packet is encrypted; drop TLS afterward.
        if not self.tds8 and resp["Encryption"] == ENCRYPT_OFF:
            self.tlsSocket = None

        server_challenge = self.recvTDS()["Data"][3:]

        # Resolve the channel binding token for the requested probe mode.
        if self._has_active_tls_channel_binding():
            channel_binding_value = (
                self.generate_cbt_from_tls_unique() if cbt_value is None else cbt_value
            )
        else:
            # No live TLS channel -> there is no real CBT to compute.
            channel_binding_value = b"" if cbt_value is None else cbt_value

        original_test_case = ntlm.TEST_CASE
        if strip_target_service:
            # impacket's TEST_CASE flag suppresses the target-name AV pair.
            ntlm.TEST_CASE = True
        try:
            type3, _ = auth_mod.ntlm_type3(
                type1=type1,
                server_challenge=server_challenge,
                username=username,
                password=password,
                domain=domain,
                nt_hash=nt_hash,
                channel_binding_value=channel_binding_value,
                service=service,
                compute_mic=True,
                version=version,
            )
        finally:
            # Always restore the global TEST_CASE flag.
            ntlm.TEST_CASE = original_test_case

        self.sendTDS(tds.TDS_SSPI, type3.getData())
        self.replies = self.parseReply(self.recvTDS()["Data"])
        return tds.TDS_LOGINACK_TOKEN in self.replies

    # -- EPA-controllable SSPI login (current user, Windows) -----------------
    def login_sspi_epa(self, *, target_spn: Optional[str], cbt_mode: str) -> bool:
        """Current-user (integrated) SSPI login with EPA bindings under control.

        ``target_spn`` becomes the service binding (None omits it); ``cbt_mode``
        in {"correct","bogus","missing"} controls the channel binding. NTLM is
        forced (not Negotiate) so the AV-pair-based EPA mechanism applies.
        """
        import sspicon
        import win32security

        resp = self._negotiate_encryption()
        self.epa_is_strict = bool(self.tds8)
        self.epa_encryption_flag = ENCRYPT_STRICT if self.tds8 else resp["Encryption"]

        client = auth_mod.SspiClient(
            package="NTLM",
            target_spn=target_spn,
            scflags=sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_CONNECTION,
        )
        type1, _ = client.step(None)
        login = self._build_login7(None, sspi=type1)
        self.sendTDS(tds.TDS_LOGIN7, login.getData())
        if not self.tds8 and resp["Encryption"] == ENCRYPT_OFF:
            self.tlsSocket = None

        server_challenge = self.recvTDS()["Data"][3:]

        sec_buffer_in = win32security.PySecBufferDescType()
        token_buf = win32security.PySecBufferType(
            client.auth.pkg_info["MaxToken"], sspicon.SECBUFFER_TOKEN
        )
        # Writing .Buffer is how pywin32 fills a security buffer, but types-pywin32
        # declares the property read-only and str-typed. Both are wrong for this API:
        # the setter exists and takes bytes.
        token_buf.Buffer = bytes(server_challenge)  # type: ignore[misc,assignment]
        sec_buffer_in.append(token_buf)

        bindings = self._resolve_sspi_channel_binding(cbt_mode)
        if bindings is not None:
            cbt_buf = win32security.PySecBufferType(
                len(bindings), sspicon.SECBUFFER_CHANNEL_BINDINGS
            )
            cbt_buf.Buffer = bindings  # type: ignore[misc,assignment]  # see token_buf above
            sec_buffer_in.append(cbt_buf)
        else:
            # "missing" mode (or no tls-unique) -> send no channel-binding buffer.
            logger.debug("SSPI EPA login: no channel-binding buffer (mode=%s)", cbt_mode)

        _, out_buffers = client.auth.authorize(sec_buffer_in)
        type3 = bytes(out_buffers[0].Buffer)

        self.sendTDS(tds.TDS_SSPI, type3)
        self.replies = self.parseReply(self.recvTDS()["Data"])
        return tds.TDS_LOGINACK_TOKEN in self.replies

    def _resolve_sspi_channel_binding(self, cbt_mode: str) -> Optional[bytes]:
        """Return SEC_CHANNEL_BINDINGS bytes for ``cbt_mode`` (or None to omit)."""
        if cbt_mode == "missing" or not getattr(self, "tls_unique", None):
            # Nothing to bind (no encryption, or caller asked to omit it).
            return None
        if cbt_mode == "bogus":
            return _sec_channel_bindings(_BOGUS_TLS_UNIQUE)
        return _sec_channel_bindings(self.tls_unique)

    def _build_login7(self, database, *, sspi: bytes):
        """Build a TDS_LOGIN7 packet carrying the given SSPI blob (Windows auth)."""
        login = tds.TDS_LOGIN()
        login["TDSVersion"] = self._get_default_login7_tds_version()
        self._set_session_login7_tds_version(login["TDSVersion"])
        login["HostName"] = self.workstation_id.encode("utf-16le")
        login["AppName"] = self.application_name.encode("utf-16le")
        login["ServerName"] = self.remoteName.encode("utf-16le")
        login["CltIntName"] = login["AppName"]
        login["ClientPID"] = 1234
        login["PacketSize"] = self.packetSize
        if database is not None:
            login["Database"] = database.encode("utf-16le")
        login["OptionFlags2"] = (
            tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON
        )
        login["SSPI"] = sspi
        login["Length"] = len(login.getData())
        return login


def _sec_channel_bindings(tls_unique: bytes) -> bytes:
    """Build a Windows ``SEC_CHANNEL_BINDINGS`` struct for the given tls-unique."""
    import struct

    app_data = b"tls-unique:" + tls_unique
    header = struct.pack("<8L", 0, 0, 0, 0, 0, 0, len(app_data), 32)
    return header + app_data


# ---------------------------------------------------------------------------
# MssqlConnection — real authenticated connection + query
# ---------------------------------------------------------------------------
@dataclass
class _Strategy:
    """One rung of the connection-strategy waterfall."""

    name: str
    server_name: str   # host string to connect to (FQDN or short)
    encrypt: str       # "true" | "strict" | "false"
    remote_name: str   # remoteName for SPN / cert matching


class MssqlConnection:
    """An authenticated TDS connection to one SQL Server, with a query helper.

    Open with :meth:`connect`; run SQL with :meth:`query`; close with
    :meth:`close` (or use as a context manager). The connection waterfall mirrors
    Go ``connectNative``: it tries encryption variants and hostname forms in
    order, but **stops immediately on an authentication error** so a wrong
    credential is never replayed across strategies (AD lockout safety).
    """

    def __init__(self) -> None:
        self._client: Optional[_Tds] = None
        self._target: Optional[Target] = None
        self._strategy_name: Optional[str] = None

    # -- context manager -----------------------------------------------------
    def __enter__(self) -> "MssqlConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def strategy(self) -> Optional[str]:
        """Name of the connection strategy that succeeded (after connect)."""
        return self._strategy_name

    def connect(self, target: str, auth: Auth, *, timeout: int = 15,
                strict_first: bool = False) -> "MssqlConnection":
        """Open a connection to *target* using *auth*; return self.

        ``strict_first`` reorders the waterfall to try TDS 8.0 strict before
        plain encrypt (use when EPA detection already found strict encryption).
        Raises the last error if every strategy fails, or an auth error as soon
        as one is seen (no further attempts).
        """
        self._target = parse_target(target)
        strategies = self._build_strategies(self._target, strict_first=strict_first)

        last_error: Optional[Exception] = None
        for strat in strategies:
            client = _Tds(strat.server_name, self._target.port, strat.remote_name)
            try:
                client.connect(timeout=timeout)
                authenticated = self._login(client, auth, strat)
            except Exception as exc:  # noqa: BLE001 — classify, then decide
                message = str(exc)
                try:
                    client.disconnect()
                except Exception:  # noqa: BLE001 — best-effort teardown
                    pass
                if is_auth_error(message):
                    # Credential failure — stop now to avoid AD account lockout.
                    logger.warning("Auth error on strategy %s for %s; stopping waterfall: %s",
                                   strat.name, target, message)
                    raise
                # Transport/TLS error — record and try the next strategy.
                logger.verbose("Strategy %s failed for %s (transport): %s",
                               strat.name, target, message)
                last_error = exc
                continue

            if authenticated:
                # Success — keep this client and remember which strategy worked.
                logger.verbose("Connection strategy %s succeeded for %s", strat.name, target)
                self._client = client
                self._strategy_name = strat.name
                return self

            # Reached LOGIN without an exception but no LOGINACK -> auth failed.
            message = client.get_error_messages() or "login rejected (no LOGINACK)"
            try:
                client.disconnect()
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass
            if is_auth_error(message):
                logger.warning("Auth rejection on strategy %s for %s; stopping waterfall: %s",
                               strat.name, target, message)
                raise SQLAuthError(message)
            logger.verbose("Strategy %s rejected login for %s (non-auth): %s",
                           strat.name, target, message)
            last_error = SQLAuthError(message)

        # Every strategy exhausted without success.
        logger.error("All connection strategies failed for %s; last error: %s", target, last_error)
        raise last_error or RuntimeError(f"all connection strategies failed for {target}")

    def _build_strategies(self, target: Target, *, strict_first: bool) -> list[_Strategy]:
        """Build the ordered waterfall (encryption × hostname-form), per Go.

        FQDN targets also get short-hostname variants (some servers only accept
        the NetBIOS name in the SPN). IP targets get a reverse-DNS remoteName so
        strict TLS cert matching has an FQDN to validate against.
        """
        host = target.host
        is_ip = _is_ip(host)

        short_host = ""
        remote_for_strict = host
        if not is_ip:
            if "." in host:
                # FQDN -> derive the short (NetBIOS) hostname.
                short_host = host.split(".", 1)[0]
        else:
            # IP -> try reverse DNS so strict TLS has a cert name to match.
            fqdn = _reverse_dns(host)
            if fqdn:
                remote_for_strict = fqdn
                logger.verbose("Resolved IP %s to %s for cert matching", host, fqdn)
            else:
                logger.verbose("No reverse DNS for %s; strict TLS may fail cert match", host)

        if strict_first:
            # EPA found strict encryption -> lead with strict.
            order = [("strict", remote_for_strict), ("true", host), ("false", host)]
        else:
            # Most common: encrypt first, then strict, then no-encrypt.
            order = [("true", host), ("strict", remote_for_strict), ("false", host)]

        strategies = [
            _Strategy(name=f"FQDN+{enc}", server_name=host, encrypt=enc, remote_name=rn)
            for enc, rn in order
        ]
        if short_host:
            # Append short-hostname encrypt + strict + no-encrypt variants.
            strategies += [
                _Strategy("short+true", short_host, "true", short_host),
                _Strategy("short+strict", short_host, "strict", remote_for_strict),
                _Strategy("short+false", short_host, "false", short_host),
            ]
        return strategies

    def _login(self, client: _Tds, auth: Auth, strat: _Strategy) -> bool:
        """Perform the login appropriate to *auth*; return True on LOGINACK.

        Note: impacket's ``_negotiate_encryption`` (called inside every login)
        decides encryption from the server's PRELOGIN response, so all strategy
        variants share the same login call — the strategy ordering matters for
        the reverse-DNS remoteName and short-host SPN, which are set on ``client``.
        """
        if self._target is None:
            # Set by connect() before any login attempt; a None here means a login was
            # driven without connecting, which is a caller bug worth naming.
            raise RuntimeError("login attempted before connect() parsed a target")
        spn = auth.spn or default_spn(strat.remote_name, self._target.port)
        if auth.kerberos_ticket:
            # Pass-the-ticket: Kerberos only (no NTLM fallback) — design D12.
            logger.verbose("Login via pass-the-ticket (Kerberos) for SPN %s", spn)
            return self._kerberos_login(client, auth)
        if auth.use_sspi:
            # Current-user SSPI (Windows SSO) with the correct channel binding.
            logger.verbose("Login via current-user SSPI for SPN %s", spn)
            return client.login_sspi_epa(target_spn=spn, cbt_mode="correct")
        if auth.is_sql_login():
            # Plain SQL login (user/pass, no domain).
            logger.verbose("Login via SQL authentication as %s", auth.username)
            return client.login(None, auth.username, auth.password or "")
        # Domain NTLMv2 (+ EPA channel binding) or pass-the-hash.
        logger.verbose("Login via domain NTLMv2%s for %s\\%s",
                       " (pass-the-hash)" if auth.nt_hash else "", auth.domain, auth.username)
        return client.login_epa(
            database=None,
            username=auth.username or "",
            password=auth.password or "",
            domain=auth.domain,
            nt_hash=auth.nt_hash,
            cbt_value=None,            # correct CBT from the live TLS channel
            service=DEFAULT_SERVICE_CLASS,
        )

    def _kerberos_login(self, client: _Tds, auth: Auth) -> bool:
        """Pass-the-ticket login: load the KRB-CRED into impacket's ccache.

        impacket's ``kerberosLogin`` reads tickets from a ccache file via the
        ``KRB5CCNAME`` env var (``useCache=True``); we materialize the base64
        ticket into a temp ccache and point impacket at it. Kerberos only.
        """
        import base64
        import os
        import tempfile

        from impacket.krb5.ccache import CCache

        if not auth.kerberos_ticket:
            # The caller reaches this method only after testing auth.kerberos_ticket, but
            # asserting it here keeps the precondition with the code that depends on it.
            raise ValueError("_kerberos_login requires auth.kerberos_ticket")
        ccache = CCache()
        ccache.fromKRBCRED(base64.b64decode(auth.kerberos_ticket, validate=True))
        fd, path = tempfile.mkstemp(suffix=".ccache")
        os.close(fd)
        ccache.saveFile(path)
        old = os.environ.get("KRB5CCNAME")
        os.environ["KRB5CCNAME"] = path
        try:
            return client.kerberosLogin(
                None,
                auth.username or "",
                domain=auth.domain,
                useCache=True,
            )
        finally:
            # Restore KRB5CCNAME and remove the temp ccache.
            if old is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = old
            try:
                os.remove(path)
            except OSError:
                logger.debug("Could not remove temp ccache %s", path)

    def query(self, sql: str, database: Optional[str] = None) -> list[dict]:
        """Run *sql* and return the result rows as a list of dicts.

        Each row is the impacket row dict (column name -> value). Raises if the
        connection is not open or the server returns an error token.
        """
        if self._client is None:
            raise RuntimeError("query() called before a successful connect()")
        logger.debug("Running query (%d chars) on db=%s", len(sql), database or "master")
        rows = self._client.RunSQLQuery(database, sql)
        # impacket returns a list of dicts already; normalize to plain dicts and
        # map SQL NULL to Python None. impacket represents a NULL column value as
        # the literal string "NULL" (see tds.MSSQL.parseRow), which would
        # otherwise serialize to the JSON string "NULL" and be indistinguishable
        # from a real "NULL" text value. Mapping it to None makes nullable
        # columns (e.g. owner_sid / instance_name) come through as JSON null.
        return [_nulls_to_none(dict(row)) for row in (rows or [])]

    def change_database(self, database: str) -> None:
        """Switch the active database (USE <db>)."""
        if self._client is None:
            raise RuntimeError("change_database() called before connect()")
        self._client.changeDB(database)

    def close(self) -> None:
        """Close the connection (idempotent)."""
        if self._client is not None:
            try:
                self._client.disconnect()
            except Exception as exc:  # noqa: BLE001 — best-effort teardown
                logger.debug("Error during disconnect (ignored): %s", exc)
            finally:
                self._client = None


class SQLAuthError(Exception):
    """A login was rejected with a credential-related (lockout-counting) error."""


# ---------------------------------------------------------------------------
# EPA detection (the 5-probe matrix + decision tree)
# ---------------------------------------------------------------------------
class EPAPrereqError(Exception):
    """Baseline login neither authenticated nor cleanly failed — EPA unknowable."""


@dataclass
class _ProbeOutcome:
    """Classified result of one EPA login probe."""

    success: bool = False
    is_untrusted_domain: bool = False
    is_login_failed: bool = False
    encryption_flag: int = ENCRYPT_OFF
    is_strict: bool = False
    error_message: str = ""


def detect_epa(target: str, auth: Auth, *, timeout: int = 15) -> dict:
    """Determine EPA enforcement for *target* using *auth* (LDAP/domain creds).

    Returns a dict with at least::

        {"forceEncryption": bool,
         "extendedProtection": "Off"|"Allowed"|"Required"|"Allowed/Required"|"Unknown",
         "strictEncryption": bool}

    ``extendedProtection`` is "Allowed/Required" only under current-user SSPI,
    where Windows always includes the AV pairs so Allowed and Required are
    indistinguishable (the uncertainty is surfaced verbatim — see memory
    ``feedback_epa_uncertainty_label``).

    Raises :class:`EPAPrereqError` if the baseline (correct-bindings) login does
    not cleanly succeed or "login failed", because then the manipulated-binding
    probes cannot be trusted.
    """
    parsed = parse_target(target)
    spn = auth.spn or default_spn(parsed.host, parsed.port)
    auth_method = "sspi" if auth.use_sspi else "explicit"
    probe = _make_prober(parsed, auth, spn, timeout=timeout)

    normal = probe("normal")
    # Prereq: baseline must authenticate or fail with a plain "login failed".
    if not normal.success and not normal.is_login_failed:
        message = normal.error_message or "credentials rejected (untrusted domain)"
        logger.error("EPA prereq failed for %s: %s", target, message)
        raise EPAPrereqError(f"EPA prereq check failed: {message}")

    force_encryption = normal.is_strict or normal.encryption_flag == ENCRYPT_REQ
    if normal.is_strict or normal.encryption_flag == ENCRYPT_REQ:
        # Encrypted connection -> probe channel-binding enforcement.
        logger.verbose("EPA: encrypted connection to %s; probing channel binding", target)
        extended = _classify_binding(probe, "bogus_cbt", "missing_cbt", auth_method)
    elif normal.encryption_flag in (ENCRYPT_OFF, ENCRYPT_ON):
        # Unencrypted connection -> probe service (SPN) binding enforcement.
        logger.verbose("EPA: unencrypted connection to %s; probing service binding", target)
        extended = _classify_binding(probe, "bogus_service", "missing_service", auth_method)
    else:
        # NOT_SUP or anything unexpected -> nothing usable to probe.
        logger.warning("EPA: unexpected encryption flag %d for %s; verdict Unknown",
                       normal.encryption_flag, target)
        extended = "Unknown"

    verdict = {
        "forceEncryption": force_encryption,
        "extendedProtection": extended,
        "strictEncryption": normal.is_strict,
        "encryptionFlag": normal.encryption_flag,
        "unmodifiedSuccess": normal.success,
    }
    logger.info("EPA verdict for %s: %s", target, verdict)
    return verdict


def _classify_binding(probe: Callable[[str], _ProbeOutcome], bogus_mode: str,
                      missing_mode: str, auth_method: str) -> str:
    """Map a bogus-then-missing probe pair to Off / Allowed / Required.

    Accepting a *bogus* binding -> EPA Off. Rejecting bogus but accepting
    *missing* -> Allowed; rejecting both -> Required. Under SSPI, both are always
    rejected when EPA is on (Windows always includes the AV pairs), so Allowed
    and Required are indistinguishable -> literal "Allowed/Required".
    """
    bogus = probe(bogus_mode)
    if not bogus.is_untrusted_domain:
        # Server accepted a garbage binding -> not checking bindings at all.
        return "Off"
    missing = probe(missing_mode)
    if missing.is_untrusted_domain:
        # Both bogus and missing rejected.
        if auth_method == "sspi":
            # SSPI cannot distinguish Allowed from Required — surface ambiguity.
            return "Allowed/Required"
        return "Required"
    # Bogus rejected but missing accepted -> server checks but does not require.
    return "Allowed"


def _make_prober(target: Target, auth: Auth, spn: str, *, timeout: int) -> Callable[[str], _ProbeOutcome]:
    """Return a ``probe(mode)`` that runs one EPA login probe on a fresh conn.

    A fresh connection per probe (matching MSSQLHound) ensures no connection
    state leaks between modes. Dispatches to the SSPI or explicit-credential
    login depending on ``auth.use_sspi``.
    """
    host = spn.split("/", 1)[1].split(":", 1)[0] if "/" in spn else target.host
    # SSPI mode_spec: (target_spn, cbt_mode) per probe mode.
    sspi_spec = {
        "normal": (spn, "correct"),
        "bogus_cbt": (spn, "bogus"),
        "missing_cbt": (spn, "missing"),
        "bogus_service": (f"cifs/{host}", "correct"),
        "missing_service": (None, "correct"),
    }
    service_class = spn.split("/", 1)[0] if "/" in spn else DEFAULT_SERVICE_CLASS

    def probe(mode: str) -> _ProbeOutcome:
        client = _Tds(target.host, target.port, target.host)
        try:
            client.connect(timeout=timeout)
            if auth.use_sspi:
                target_spn, cbt_mode = sspi_spec[mode]
                authenticated = client.login_sspi_epa(target_spn=target_spn, cbt_mode=cbt_mode)
            else:
                params = _explicit_mode_params(mode, service_class)
                authenticated = client.login_epa(
                    database=None,
                    username=auth.username or "",
                    password=auth.password or "",
                    domain=auth.domain,
                    nt_hash=auth.nt_hash,
                    **params,
                )
            enc, strict = client.epa_encryption_flag, client.epa_is_strict
            if authenticated:
                logger.debug("EPA probe %s on %s: success", mode, target.host)
                return _ProbeOutcome(success=True, encryption_flag=enc, is_strict=strict)
            outcome = _classify_error_text(client.get_error_messages())
            outcome.encryption_flag = enc
            outcome.is_strict = strict
            logger.debug("EPA probe %s on %s: %s", mode, target.host, outcome.error_message)
            return outcome
        except Exception as ex:  # noqa: BLE001 — one bad probe must not abort all
            logger.debug("EPA probe %s on %s raised: %s", mode, target.host, ex)
            return _ProbeOutcome(
                error_message=str(ex),
                encryption_flag=getattr(client, "epa_encryption_flag", ENCRYPT_OFF),
                is_strict=getattr(client, "epa_is_strict", False),
            )
        finally:
            try:
                client.disconnect()
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass

    return probe


def _explicit_mode_params(mode: str, service_class: str) -> dict:
    """Map an EPA probe mode to ``_Tds.login_epa`` keyword arguments."""
    if mode == "normal":
        return {"cbt_value": None, "service": service_class, "strip_target_service": False}
    if mode == "bogus_cbt":
        return {"cbt_value": BOGUS_CBT, "service": service_class, "strip_target_service": False}
    if mode == "missing_cbt":
        return {"cbt_value": b"", "service": service_class, "strip_target_service": False}
    if mode == "bogus_service":
        return {"cbt_value": None, "service": "cifs", "strip_target_service": False}
    if mode == "missing_service":
        return {"cbt_value": None, "service": "", "strip_target_service": True}
    raise ValueError(f"unknown EPA probe mode: {mode!r}")


def _classify_error_text(text: str) -> _ProbeOutcome:
    """Classify a server error string into an unauthenticated outcome."""
    lowered = text.lower()
    return _ProbeOutcome(
        is_untrusted_domain=_UNTRUSTED_DOMAIN_TEXT in lowered,
        is_login_failed=_LOGIN_FAILED_TEXT in lowered,
        error_message=text,
    )


# ---------------------------------------------------------------------------
# DNS / IP helpers
# ---------------------------------------------------------------------------
def _is_ip(host: str) -> bool:
    """True when *host* is a bare IPv4/IPv6 literal."""
    import ipaddress

    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _reverse_dns(ip: str) -> Optional[str]:
    """Best-effort reverse DNS lookup, returning an FQDN or None."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".") if name else None
    except (socket.herror, socket.gaierror, OSError) as ex:
        logger.debug("Reverse DNS failed for %s: %s", ip, ex)
        return None


__all__ = [
    "Auth",
    "BOGUS_CBT",
    "EPAPrereqError",
    "MssqlConnection",
    "SQLAuthError",
    "Target",
    "default_spn",
    "detect_epa",
    "is_auth_error",
    "parse_target",
]
