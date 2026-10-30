# Generalized from sccm/sccm/src/openhound_sccm/clients/http_auth.py.
#
# "Generalize" per design spec §2.1 / §9: this is the same Windows-auth token
# minting the SCCM HTTP client proved out, with everything HTTP/SCCM-specific
# stripped so any protocol (TDS/MSSQL, HTTP, LDAP, …) can reuse it:
#   - the SPN is now a caller-supplied argument (not hard-coded "HTTP/<host>"),
#   - the GSS checksum flags are a caller-supplied argument (the SCCM file froze
#     them to the http.sys-friendly set; here the default mirrors impacket but a
#     caller can pass any combination, e.g. the EPA/TDS-friendly set),
#   - the realm is derived from the SPN/caller rather than an HTTP-specific field,
#   - no SPNEGO Negotiate "ladder", no AuthMode enum, no anonymous rung — those
#     are HTTP-handshake concerns and live in the consumer, not the shared lib.
#
# What is kept (the genuinely reusable core):
#   - Kerberos AP-REQ minting from a password / NT-hash-as-RC4 key / base64
#     KRB-CRED (.kirbi) ccache (pass-the-ticket), wrapped in SPNEGO NegTokenInit.
#   - NTLM type1/type3 minting with an optional channel-binding value and target
#     SPN service class (the EPA AV pairs), incl. the MIC over the three messages.
#   - Current-user SSPI (Windows) ClientAuth helpers (Negotiate or NTLM).
"""Reusable Windows-auth token minting for OpenHound collectors.

Pure-Python (impacket) + Windows-only (pywin32) helpers that mint the auth
tokens shared across protocols. Three families:

* **Kerberos** — :class:`KerberosToken` builds a single AP-REQ for a target SPN
  from a password, an NT hash (used as the RC4 key), or a base64 KRB-CRED
  (``.kirbi``) ticket (pass-the-ticket), and wraps it in an SPNEGO NegTokenInit.
* **NTLM** — :func:`ntlm_type1` / :func:`ntlm_type3` mint the negotiate and
  authenticate messages, with an optional channel-binding value (EPA CBT) and a
  target SPN service class (EPA service binding), including the MIC.
* **Current-user SSPI** — :func:`sspi_available` + :class:`SspiClient` for
  passwordless Windows single sign-on (Negotiate or NTLM), Windows-only.

These are protocol-agnostic: the caller supplies the SPN, so the same code mints
tokens for ``MSSQLSvc/host:1433``, ``HTTP/host``, ``ldap/host``, etc.
"""

from __future__ import annotations

import datetime
import importlib
import ipaddress
import struct
import sys
from typing import Any, Optional

from impacket import ntlm
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.gssapi import (
    CheckSumField,
    GSS_C_INTEG_FLAG,
    GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
    KRB5_AP_REQ,
)
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3, hmac_md5
from impacket.spnego import (
    ASN1_AID,
    ASN1_OID,
    SPNEGO_NegTokenInit,
    TypesMech,
    asn1encode,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from ..logging.log_context import get_logger
from .kerberos_io import kerberos_exchange
from .kerberos import (
    acquisition_failure,
    KerberosCredentials,
    TicketMaterial,
    load_kerberos_credentials,
    validate_kerberos_identity,
    validate_secret_sources,
)
from ..logging.authentication import authentication_diagnostics

logger = get_logger(__name__)

# The conventional empty LM hash, prepended to a bare NT hash so impacket
# receives the LMHASH:NTHASH form it expects (identical to the SCCM source).
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

# Default SQL Server service class for the NTLM service-binding AV pair. The
# caller may override per protocol; "MSSQLSvc" is the common case for this lib.
DEFAULT_SERVICE_CLASS = "MSSQLSvc"

# Default GSS checksum flags for the Kerberos authenticator. Mirrors impacket's
# integrated-auth set (Integ/Sequence/Replay/Mutual) MINUS GSS_C_DCE_STYLE and
# GSS_C_CONF. A caller that needs a different set (e.g. http.sys quirks) passes
# its own; the SCCM HTTP client did exactly this. Validated live for MSSQL.
DEFAULT_GSS_FLAGS = (
    GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG
)

# SPNEGO mechanism OIDs.
_MS_KRB5 = TypesMech["MS KRB5 - Microsoft Kerberos 5"]
_KRB5 = TypesMech["KRB5 - Kerberos 5"]


# --- small shared helpers ----------------------------------------------------


def format_hashes(nt_hash: Optional[str]) -> Optional[str]:
    """Normalize an NT hash to impacket's ``LMHASH:NTHASH`` form (or None)."""
    if not nt_hash:
        # No hash supplied -> caller should fall back to password-based auth.
        return None
    if ":" in nt_hash:
        # Already a full LM:NT pair — pass through unchanged.
        return nt_hash
    # Bare NT hash — prepend the conventional empty LM hash.
    return f"{EMPTY_LM_HASH}:{nt_hash}"


def split_user_domain(username: str, default_domain: str) -> tuple[str, str]:
    """Split ``DOMAIN\\user`` or ``user@domain`` into ``(domain, user)``."""
    if "\\" in username:
        # NetBIOS form DOMAIN\user.
        domain, user = username.split("\\", 1)
        return domain, user
    if "@" in username:
        # UPN form user@domain.
        user, domain = username.split("@", 1)
        return domain, user
    # Bare sAMAccountName — caller-supplied default domain applies.
    return default_domain, username


def split_hashes(nt_hash: Optional[str]) -> tuple[str, str]:
    """Return ``(lmhash_hex, nthash_hex)`` from an NT hash, or ``("", "")``.

    Empty *strings* (not bytes) are returned when no hash is supplied: impacket's
    NTOWFv2 keys on ``hash != ''`` (a str compare), so ``b""`` would mislead it
    into HMACing with empty bytes instead of deriving the hash from the password.
    """
    hashes = format_hashes(nt_hash)
    if not hashes:
        # No hash -> impacket derives the key from the password.
        return "", ""
    lm, nt = hashes.split(":")
    return lm, nt


# --- auth-ladder selection ---------------------------------------------------


def is_ip(host: str) -> bool:
    """True when *host* is a bare IP literal (no Kerberos SPN can be formed for it)."""
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def choose_auth(
    *,
    username: Optional[str],
    password: Optional[str],
    nt_hash: Optional[str],
    ticket: Optional[str],
    target_host: str,
    sspi_available: bool,
) -> list[str]:
    """Resolve the ordered auth rungs to attempt against a target.

    Shared credential-precedence ladder used by the HTTP (Negotiate) client and
    the WMI client. Precedence (explicit creds win, then current-user SSPI, then
    anonymous):

      1. ticket                     -> ["kerberos"]         (no NTLM fallback)
      2. username + (password|hash) -> ["kerberos","ntlm"]  (Kerberos skipped when
                                        the target is a bare IP -> ["ntlm"], since
                                        no SPN can be formed for an IP)
      3. sspi_available             -> ["sspi"]
      4. otherwise                  -> ["anonymous"]
    """
    if ticket:
        logger.debug("auth ladder: pass-the-ticket (Kerberos only) for %s", target_host)
        return ["kerberos"]
    if username and (password or nt_hash):
        if is_ip(target_host):
            logger.verbose(
                "auth ladder: %s is a bare IP; skipping Kerberos (no SPN), NTLM only",
                target_host,
            )
            return ["ntlm"]
        logger.debug(
            "auth ladder: explicit creds -> Kerberos, NTLM fallback for %s", target_host
        )
        return ["kerberos", "ntlm"]
    if sspi_available:
        logger.debug("auth ladder: current-user SSPI for %s", target_host)
        return ["sspi"]
    logger.verbose("auth ladder: no creds and no SSPI; anonymous for %s", target_host)
    return ["anonymous"]


# --- NTLM token minting ------------------------------------------------------


def ntlm_type1(*, domain: str = "", workstation: str = "", version=None):
    """Mint the NTLM NEGOTIATE (type1) message (NTLMv2 requested).

    Returns the impacket type1 object; pass it back to :func:`ntlm_type3` so the
    MIC is computed over the same negotiate bytes the server saw.
    """
    return getNTLMSSPType1(workstation, domain, use_ntlmv2=True, version=version)


def ntlm_type3(
    *,
    type1,
    server_challenge: bytes,
    username: str,
    password: str = "",
    domain: str = "",
    nt_hash: Optional[str] = None,
    channel_binding_value: bytes = b"",
    service: str = DEFAULT_SERVICE_CLASS,
    omit_target_service: bool = False,
    compute_mic: bool = True,
    version=None,
):
    """Mint the NTLM AUTHENTICATE (type3) message, optionally with the MIC.

    ``channel_binding_value`` becomes the EPA channel-binding AV pair (``b""``
    omits it); ``service`` is the SPN service class for the target-name AV pair.
    ``omit_target_service`` removes that pair only from this login's message,
    for the missing-service EPA probe. It never changes provider globals.
    When ``compute_mic`` is True the MIC is computed over negotiate + challenge +
    authenticate (required by modern SQL Server), mirroring impacket's own login.

    Returns ``(type3, exported_session_key)``.
    """
    lm, nt = split_hashes(nt_hash)
    if nt_hash and not nt:
        logger.error("NTLM hash input is missing its NT portion")
        raise ValueError("NTLM hash input requires an NT hash")
    # Kerberos callers need hexadecimal text from split_hashes. This NTLM
    # provider instead requires decoded bytes, so convert only at its boundary.
    lm_bytes = _ntlm_hash_bytes(lm)
    nt_bytes = _ntlm_hash_bytes(nt)
    type3, exported_session_key = getNTLMSSPType3(
        type1,
        server_challenge,
        username,
        password,
        domain,
        lm_bytes,
        nt_bytes,
        service=service,
        use_ntlmv2=True,
        channel_binding_value=channel_binding_value,
        version=version,
    )
    if omit_target_service:
        exported_session_key = _omit_ntlm_target_service(
            type3,
            server_challenge=server_challenge,
            response_key=ntlm.NTOWFv2(username, password, domain, nt_bytes),
            exported_session_key=exported_session_key,
        )
    # Ordinary calls keep the provider message unchanged until the existing MIC
    # step below. There is no operational decision to report for that default.
    if compute_mic:
        # MIC = HMAC-MD5(sessionKey, negotiate || challenge || authenticate),
        # computed with the MIC field zeroed first (impacket convention).
        from impacket.ntlm import NTLMAuthChallenge

        type3["MIC"] = b"\x00" * 16
        type3["MIC"] = hmac_md5(
            exported_session_key,
            type1.getData()
            + NTLMAuthChallenge(server_challenge).getData()
            + type3.getData(),
        )
        logger.debug(
            "NTLM type3 MIC computed (service=%s, cbt_len=%d)",
            service,
            len(channel_binding_value),
        )
    else:
        # Caller does not want a MIC (rare) — leave the field as impacket set it.
        logger.debug("NTLM type3 minted without MIC (service=%s)", service)
    return type3, exported_session_key


def _ntlm_hash_bytes(value: str) -> bytes | str:
    """Decode one hash without changing the provider's empty-string sentinel."""
    if not value:
        # The provider compares with the string '', not b'', to select password
        # derivation. There is no hash or operational decision to report here.
        return ""
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        logger.error("NTLM hash input is not valid hexadecimal text")
        raise ValueError("NTLM hashes must be 16-byte hexadecimal values") from None
    if len(decoded) != 16:
        logger.error("NTLM hash input has an invalid decoded length")
        raise ValueError("NTLM hashes must be 16-byte hexadecimal values")
    return decoded


def _omit_ntlm_target_service(
    message: ntlm.NTLMAuthChallengeResponse,
    *,
    server_challenge: bytes,
    response_key: bytes,
    exported_session_key: bytes,
) -> bytes:
    """Remove one owned NTLMv2 field and return the matching signing key.

    This small provider boundary follows impacket 0.13.1's NTLMv2 layout: a
    16-byte proof, a 28-byte client-challenge header, then its named fields.
    Keep the provider's timestamp, nonce and other fields. Its existing crypto
    functions update the proof and keys; the caller computes the final MIC last.
    """
    response = message["ntlm"]
    proof_length = 16
    fields_offset = proof_length + 28
    if (
        not isinstance(response, bytes)
        or len(response) < fields_offset + 4
        or response[proof_length : proof_length + 8] != b"\x01\x01" + b"\x00" * 6
    ):
        logger.error("Missing-service EPA probe requires a provider NTLMv2 response")
        raise ValueError("Missing-service EPA probe requires an NTLMv2 response")

    fields = ntlm.AV_PAIRS(response[fields_offset:])
    if fields.getData() != response[fields_offset:]:
        # Refuse a changed provider layout instead of discarding bytes that this
        # adapter does not understand (for example, an added response trailer).
        logger.error("Missing-service EPA probe received unsupported NTLMv2 fields")
        raise ValueError("Unsupported NTLMv2 field layout for missing-service probe")
    if fields[ntlm.NTLMSSP_AV_TARGET_NAME] is None:
        logger.debug("NTLM target service is already absent from this login")
        return exported_session_key

    del fields[ntlm.NTLMSSP_AV_TARGET_NAME]
    client_challenge = response[proof_length:fields_offset] + fields.getData()
    challenge = ntlm.NTLMAuthChallenge(server_challenge)
    proof = hmac_md5(response_key, challenge["challenge"] + client_challenge)
    message["ntlm"] = proof + client_challenge

    # For NTLMv2, the provider's KXKEY is exactly this session base key.
    session_base_key = hmac_md5(response_key, proof)
    if challenge["flags"] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
        # Preserve the provider's random signing key, but encrypt it with the
        # updated key derived from this message's new proof.
        message["session_key"] = ntlm.generateEncryptedSessionKey(
            session_base_key, exported_session_key
        )
        logger.debug("NTLM target service omitted; exchanged session key updated")
        return exported_session_key

    logger.debug("NTLM target service omitted; direct signing key updated")
    return session_base_key


# --- Kerberos token minting --------------------------------------------------


class KerberosToken:
    """Mint a single Kerberos AP-REQ (SPNEGO-wrapped) for a target SPN.

    Sources a service ticket for ``spn`` from one of:
      * a base64 KRB-CRED (``.kirbi``) ticket — used directly if it already holds
        a service ticket for the SPN, else its TGT requests one (pass-the-ticket);
      * a password / NT hash — a fresh TGT then a service ticket from the KDC.

    The first :meth:`ap_req_spnego` call performs the KDC exchange; the result is
    cached so repeated calls only rebuild the cheap AP-REQ (no repeat round-trip).
    """

    def __init__(
        self,
        *,
        spn: str,
        realm: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        nt_hash: Optional[str] = None,
        ticket: Optional[str] = None,
        credentials: KerberosCredentials | None = None,
        kdc_host: Optional[str] = None,
        gss_flags: int = DEFAULT_GSS_FLAGS,
        mutual_auth: bool = True,
        channel_binding: bytes | None = None,
    ) -> None:
        validate_secret_sources(
            password=password or None,
            nt_hash=nt_hash or None,
            ticket=ticket,
            loaded_credentials=credentials,
        )
        if credentials is not None:
            validate_kerberos_identity(credentials, username, None)
        self._spn = spn
        self._realm = realm.upper()
        self._username = username
        self._password = password or ""
        self._lm, self._nt = split_hashes(nt_hash)
        self._kdc_host = kdc_host
        self._gss_flags = gss_flags
        self._mutual_auth = mutual_auth
        self._channel_binding = channel_binding
        # Cached (tgs_rep_bytes, cipher, session_key).
        self._service: Optional[tuple] = None
        if credentials is not None and ticket is not None:
            logger.error("Both loaded and encoded Kerberos credentials were supplied")
            raise ValueError("Supply loaded Kerberos credentials or a ticket, not both")
        self._credentials = credentials
        if ticket is not None:
            self._credentials = load_kerberos_credentials(
                ticket=ticket, username=username
            )
        if self._credentials is not None:
            # The supplied ticket's own principal identifies its client realm.
            self._realm = self._credentials.realm
            self._username = self._credentials.username

    def ap_req_spnego(self) -> bytes:
        """Return the SPNEGO NegTokenInit wrapping a fresh AP-REQ for the SPN."""
        if self._service is None:
            # First call: do the (possibly cached-from-ticket) KDC exchange once.
            self._service = self._service_ticket()
        return self._build_blob(*self._service)

    def _service_ticket(self):
        """Return ``(tgs_rep_bytes, cipher, session_key)`` for the target SPN."""
        with kerberos_exchange():
            return self._request_service_ticket()

    def _request_service_ticket(self):
        """Let the existing provider create tickets inside the owned I/O scope."""
        if self._credentials is not None:
            material = self._credentials.service_ticket(self._spn, self._kdc_host)
            return material["KDC_REP"], material["cipher"], material["sessionKey"]

        # No ticket: derive a TGT from the password/hash, then a service ticket.
        logger.verbose(
            "Kerberos: requesting TGT+TGS for %s from KDC %s", self._spn, self._kdc_host
        )
        client = Principal(
            self._username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        with authentication_diagnostics():
            try:
                tgt, cipher, _, sk = getKerberosTGT(
                    client,
                    self._password,
                    self._realm,
                    self._lm,
                    self._nt,
                    b"",
                    self._kdc_host,
                )
            except Exception as error:
                raise acquisition_failure(error) from None
            tgs, cipher, _, sk = getKerberosTGS(
                Principal(
                    self._spn, type=constants.PrincipalNameType.NT_SRV_INST.value
                ),
                self._realm,
                self._kdc_host,
                tgt,
                cipher,
                sk,
            )
        return tgs, cipher, sk

    def service_material(self) -> TicketMaterial:
        """Expose the selected ticket to a protocol client without a cache file."""
        if self._service is None:
            self._service = self._service_ticket()
        # Only the protocol adapter receives these untyped provider objects.
        reply, cipher, key = self._service
        return {"KDC_REP": reply, "cipher": cipher, "sessionKey": key}

    def _build_blob(self, tgs_bytes: bytes, cipher, session_key) -> bytes:
        """Assemble the AP-REQ and wrap it in an SPNEGO NegTokenInit."""
        tgs_rep = decoder.decode(tgs_bytes, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs_rep["ticket"])
        client_name = Principal()
        client_name.from_asn1(tgs_rep, "crealm", "cname")

        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = constants.encodeFlags(
            [constants.APOptions.mutual_required.value] if self._mutual_auth else []
        )
        seq_set(ap_req, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = str(tgs_rep["crealm"])
        seq_set(authenticator, "cname", client_name.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)
        authenticator["cksum"] = noValue
        authenticator["cksum"]["cksumtype"] = 0x8003
        chk = CheckSumField()
        chk["Lgth"] = 16
        # Caller-controllable GSS checksum flags (the generalization seam).
        chk["Flags"] = self._gss_flags
        if self._channel_binding is not None:
            # LDAP over TLS binds the authenticator to this connection's certificate.
            chk["Bnd"] = self._channel_binding
        authenticator["cksum"]["checksum"] = chk.getData()
        authenticator["seq-number"] = 0

        encrypted = cipher.encrypt(session_key, 11, encoder.encode(authenticator), None)
        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = cipher.enctype
        ap_req["authenticator"]["cipher"] = encrypted

        mech_token = struct.pack("B", ASN1_AID) + asn1encode(
            struct.pack("B", ASN1_OID)
            + asn1encode(_KRB5)
            + KRB5_AP_REQ
            + encoder.encode(ap_req)
        )
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [_MS_KRB5]
        blob["MechToken"] = mech_token
        return blob.getData()


# --- Current-user SSPI (Windows only) ----------------------------------------


def sspi_available() -> bool:
    """True only on Windows with the pywin32 SSPI modules importable.

    Mirrors the SCCM capability gate (``http_auth._sspi_negotiate_available``).
    """
    if sys.platform != "win32":
        # SSPI is a Windows API — never available elsewhere.
        return False
    try:
        importlib.import_module("sspi")
        importlib.import_module("sspicon")
        importlib.import_module("win32security")
        return True
    except ImportError:
        # pywin32 not installed — caller must use explicit credentials.
        logger.debug(
            "SSPI requested but pywin32 (sspi/sspicon/win32security) is not importable"
        )
        return False


class SspiClient:
    """Thin wrapper over pywin32 ``sspi.ClientAuth`` for current-user SSO.

    ``package`` is "Negotiate" or "NTLM" (NTLM is forced where the EPA AV-pair
    mechanism must apply). ``target_spn`` is the SPN the server is registered
    under. ``scflags`` lets the caller request integrity/connection semantics.
    Windows-only; construct only after :func:`sspi_available` returns True.
    """

    def __init__(
        self,
        *,
        package: str,
        target_spn: Optional[str],
        scflags: Optional[int] = None,
    ) -> None:
        import sspi  # Windows-only; imported lazily so the module loads anywhere

        # dict[str, Any]: the values are heterogeneous (a str|None SPN and an int flag set).
        kwargs: dict[str, Any] = {"targetspn": target_spn or None}
        if scflags is not None:
            # Caller controls ISC_REQ_* flags (e.g. INTEGRITY|CONNECTION for NTLM).
            kwargs["scflags"] = scflags
        self._auth = sspi.ClientAuth(package, **kwargs)

    @property
    def auth(self):
        """The underlying pywin32 ClientAuth (for advanced buffer building)."""
        return self._auth

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        """Advance the SSPI handshake; returns ``(out_token, done)``.

        ``done`` is True when SSPI reports SEC_E_OK (error == 0); the caller may
        still continue based on its own protocol state for an optional mutual leg.
        """
        error, buffers = self._auth.authorize(server_token if server_token else None)
        token = bytes(buffers[0].Buffer) if buffers else b""
        return token, error == 0


__all__ = [
    "DEFAULT_GSS_FLAGS",
    "DEFAULT_SERVICE_CLASS",
    "EMPTY_LM_HASH",
    "KerberosToken",
    "SspiClient",
    "format_hashes",
    "ntlm_type1",
    "ntlm_type3",
    "split_hashes",
    "split_user_domain",
    "sspi_available",
]
