"""Load one explicit Kerberos identity without changing the process ticket cache.

Impacket 0.13.1 supplies file parsing, ticket decoding, key use, and KDC traffic.
This boundary selects the intended identity and service exactly; it never treats
an unrelated first credential as a TGT or rewrites another service's ticket.
"""

from __future__ import annotations

import base64
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict

from impacket.krb5 import constants
from impacket.krb5.ccache import CCache, Credential
from impacket.krb5.keytab import Keytab
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.types import Principal

from ..logging import get_logger
from ..logging.authentication import authentication_diagnostics
from .kerberos_io import kerberos_exchange
from .operations import ReadControl, ReadStoppedError, current_read_operation

logger = get_logger(__name__)
_MAX_INPUT_BYTES = 16 * 1024 * 1024
_KEY_PREFERENCE = (18, 17, 23)  # AES-256, AES-128, then RC4, as in impacket.


class TicketMaterial(TypedDict):
    """Impacket's direct-ticket argument format, isolated at its untyped API.

    Cipher/key implementations differ by encryption type and have no published
    type stubs. Keep those two provider objects at this narrow boundary.
    """

    KDC_REP: bytes
    cipher: Any
    sessionKey: Any


class CredentialInputError(ValueError):
    """An explicit credential source is malformed, ambiguous, or mismatched."""


class KerberosAcquisitionError(RuntimeError):
    """The selected identity could not obtain a ticket; do not retry its secret."""


def acquisition_failure(error: Exception) -> KerberosAcquisitionError:
    """Keep a KDC's numeric reason without copying a provider's packet contents."""
    if isinstance(error, TimeoutError) and current_read_operation() is not None:
        # Socket timeouts can return just before the monotonic deadline because
        # Windows rounds their milliseconds. Keep the opted-in stop meaning.
        logger.warning("The controlled Kerberos ticket request timed out")
        raise ReadStoppedError("Kerberos ticket exchange timed out") from None
    code_reader = getattr(error, "getErrorCode", None)
    code = code_reader() if callable(code_reader) else None
    detail = f" (KDC error {code})" if isinstance(code, int) else ""
    logger.error("Kerberos ticket acquisition failed%s", detail)
    return KerberosAcquisitionError(
        f"Could not obtain a Kerberos ticket for the selected identity{detail}"
    )


def validate_secret_sources(**sources: object) -> None:
    """Reject competing credential families without including their values."""
    selected = [name for name, value in sources.items() if value is not None]
    if len(selected) > 1:
        logger.error("More than one authentication secret source was selected")
        raise CredentialInputError("Choose only one of " + ", ".join(selected))


def _principal(text: str) -> tuple[str, str]:
    """Separate a complete Kerberos principal from its realm."""
    username, separator, realm = text.rpartition("@")
    if not separator or not username or not realm:
        logger.error("Kerberos source contains an incomplete principal")
        raise CredentialInputError(
            "Kerberos source has no complete principal and realm"
        )
    return username, realm.upper()


def _identity_hint(
    username: str | None, realm: str | None
) -> tuple[str | None, str | None]:
    """Accept Windows/UPN input while keeping NetBIOS names distinct from realms."""
    if username and "\\" in username:
        # A Windows prefix is not necessarily the DNS Kerberos realm.
        username = username.split("\\", 1)[1]
    if username and "@" in username:
        username, supplied_realm = _principal(username)
        if realm and realm.casefold() != supplied_realm.casefold():
            logger.error("Username and explicit Kerberos realm disagree")
            raise CredentialInputError("Username and Kerberos realm disagree")
        realm = supplied_realm
    return username or None, realm.upper() if realm else None


def _read_file(path: str | Path) -> bytes:
    """Read a bounded secret file; do not copy its path/content into diagnostics."""
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(_MAX_INPUT_BYTES + 1)
    except OSError:
        logger.error("The selected Kerberos credential file could not be read")
        raise CredentialInputError(
            "Cannot read the selected Kerberos credential file"
        ) from None
    if len(data) > _MAX_INPUT_BYTES:
        logger.error("Kerberos credential file exceeds the input limit")
        raise CredentialInputError("Kerberos credential files may not exceed 16 MiB")
    return data


def _keytab_entries(data: bytes) -> bytes:
    """Remove legal deleted-entry holes before impacket parses keytab v2 entries.

    The pinned parser tries to decode holes as principals. Entry sizes are part
    of the MIT keytab format, so this small framing pass skips them without
    decoding or deriving any keys itself.
    """
    output = bytearray(data[:2])
    position = 2
    while position < len(data):
        if len(data) - position < 4:
            logger.error("Keytab has an incomplete entry header")
            raise CredentialInputError("Keytab contains an incomplete entry")
        size = struct.unpack_from(">i", data, position)[0]
        if size == 0:
            break  # MIT keytab v2 defines a zero-length record as end-of-file.
        end = position + 4 + abs(size)
        if end > len(data):
            logger.error("Keytab entry extends beyond the supplied file")
            raise CredentialInputError("Keytab contains an incomplete entry")
        if size > 0:
            output.extend(data[position:end])
        # Negative entries are unused file space, not failed reads.
        position = end
    return bytes(output)


@dataclass
class KerberosCredentials:
    """One loaded identity, shared read-only tickets and one guarded keytab TGT.

    A keytab obtains its TGT once, including a cached failure. Concurrent SQL
    and LDAP users cannot repeatedly submit a bad key or borrow another cache.
    Service tickets are requested for the caller's complete SPN, including port.
    Never serialize this object into collection settings or graph output.
    """

    username: str
    realm: str
    source: str
    _cache: CCache | None = field(default=None, repr=False)
    _aes_key: bytes = field(default=b"", repr=False)
    _nt_hash: bytes = field(default=b"", repr=False)
    _tgt: TicketMaterial | None = field(default=None, init=False, repr=False)
    _tgt_failed: bool = field(default=False, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    def __post_init__(self) -> None:
        sources = (
            int(self._cache is not None) + bool(self._aes_key) + bool(self._nt_hash)
        )
        if not self.username or not self.realm or sources != 1:
            logger.error(
                "Loaded Kerberos credentials have no single usable identity/source"
            )
            raise CredentialInputError(
                "Loaded Kerberos credentials need one identity and credential source"
            )
        self.realm = self.realm.upper()

    def prepare(
        self, kdc_host: str | None = None, *, read_control: ReadControl | None = None
    ) -> None:
        """Acquire one keytab TGT before starting parallel protocol workers.

        A failed key is submitted once. Successful workers receive its TGT,
        rather than independently resubmitting the key from the original file.
        Existing ticket/cache sources require no KDC request at this boundary.
        """
        if self._cache is not None:
            return  # Supplied tickets are checked for the requested service later.
        with kerberos_exchange(read_control):
            self._ticket_granting_ticket(kdc_host)

    def _cached(self, server: str) -> Credential | None:
        if self._cache is None:
            # Keytabs have keys, not a pre-existing credential list.
            return None
        requested_name, _, requested_realm = server.partition("@")
        for credential in self._cache.credentials:
            name, realm = _principal(credential["server"].prettyPrint().decode("utf-8"))
            if name.casefold() != requested_name.casefold() or (
                requested_realm and realm.casefold() != requested_realm.casefold()
            ):
                # Never use impacket's any-SPN/port substitution shortcut here.
                continue
            if int(credential["time"]["endtime"]) <= time.time():
                logger.debug(
                    "Selected cached ticket is expired; checking other supplied tickets"
                )
                continue
            return credential
        logger.debug("No unexpired supplied ticket matches the requested service")
        return None

    def _ticket_granting_ticket(self, kdc_host: str | None) -> TicketMaterial:
        if self._cache is not None:
            credential = self._cached(f"krbtgt/{self.realm}@{self.realm}")
            if credential is None:
                logger.error("Supplied cache has no usable home-realm TGT")
                raise CredentialInputError(
                    "No matching service ticket or unexpired realm TGT in the supplied credentials"
                )
            supplied = credential.toTGT()
            return {
                "KDC_REP": supplied["KDC_REP"],
                "cipher": supplied["cipher"],
                "sessionKey": supplied["sessionKey"],
            }
        with self._lock:
            if self._tgt_failed:
                logger.debug(
                    "Reusing the selected identity's previous acquisition failure"
                )
                raise KerberosAcquisitionError(
                    "Kerberos ticket acquisition already failed for this identity"
                )
            if self._tgt is None:
                try:
                    with authentication_diagnostics():
                        reply, cipher, _, key = getKerberosTGT(
                            Principal(
                                self.username,
                                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
                            ),
                            "",
                            self.realm,
                            b"",
                            self._nt_hash,
                            self._aes_key,
                            kdc_host,
                        )
                    self._tgt = {"KDC_REP": reply, "cipher": cipher, "sessionKey": key}
                except Exception as error:
                    self._tgt_failed = True
                    raise acquisition_failure(error) from None
            # An existing TGT belongs to this object and never comes from the environment.
            return self._tgt

    def service_ticket(self, spn: str, kdc_host: str | None = None) -> TicketMaterial:
        """Return an exact cached service ticket or request one using this identity."""
        with kerberos_exchange():
            return self._service_ticket(spn, kdc_host)

    def _service_ticket(self, spn: str, kdc_host: str | None) -> TicketMaterial:
        credential = self._cached(spn)
        if credential is not None:
            logger.debug("Using the supplied exact service ticket")
            supplied = credential.toTGS()
            return {
                "KDC_REP": supplied["KDC_REP"],
                "cipher": supplied["cipher"],
                "sessionKey": supplied["sessionKey"],
            }
        tgt = self._ticket_granting_ticket(kdc_host)
        with authentication_diagnostics():
            reply, cipher, _, key = getKerberosTGS(
                Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value),
                self.realm,
                kdc_host,
                tgt["KDC_REP"],
                tgt["cipher"],
                tgt["sessionKey"],
            )
        return {"KDC_REP": reply, "cipher": cipher, "sessionKey": key}


def validate_kerberos_identity(
    credentials: KerberosCredentials,
    username: str | None,
    realm: str | None,
) -> None:
    """Reject a loaded source selected alongside a different identity hint."""
    username, realm = _identity_hint(username, realm)
    if (username and username.casefold() != credentials.username.casefold()) or (
        realm and realm != credentials.realm
    ):
        logger.error("Loaded Kerberos credentials do not match the selected identity")
        raise CredentialInputError(
            "Loaded Kerberos credentials do not match the selected username or realm"
        )


def _load_keytab(
    keytab_file: str | Path,
    username: str | None,
    realm: str | None,
) -> KerberosCredentials:
    """Select one keytab identity and its newest supported key."""
    data = _read_file(keytab_file)
    if data[:2] != b"\x05\x02":
        raise CredentialInputError("Only MIT keytab version 2 is supported")
    keytab = Keytab(_keytab_entries(data))
    entries = [entry for entry in keytab.entries if not entry.deleted]
    matches = []
    for entry in entries:
        account, entry_realm = _principal(
            entry.main_part["principal"].prettyPrint().decode("utf-8")
        )
        if (username is None or account.casefold() == username.casefold()) and (
            realm is None or entry_realm == realm
        ):
            matches.append((account, entry_realm, entry))
        # Other principals are valid but cannot supply this identity.
    identities = {
        (account.casefold(), entry_realm) for account, entry_realm, _ in matches
    }
    if len(identities) != 1:
        raise CredentialInputError(
            "Keytab identity is missing or ambiguous; supply its username and realm"
        )
    account, selected_realm, _ = matches[0]
    latest_version = max(
        entry.kvno or entry.main_part["vno8"] for _, _, entry in matches
    )
    candidates = [
        entry
        for _, _, entry in matches
        if (entry.kvno or entry.main_part["vno8"]) == latest_version
        and entry.main_part["keyblock"]["keytype"] in _KEY_PREFERENCE
    ]
    if not candidates:
        raise CredentialInputError(
            "Keytab has no supported key at its newest key version"
        )
    selected = min(
        candidates,
        key=lambda entry: _KEY_PREFERENCE.index(entry.main_part["keyblock"]["keytype"]),
    )
    key_type = selected.main_part["keyblock"]["keytype"]
    key_bytes = bytes(selected.main_part["keyblock"]["keyvalue"]["data"])
    if len(key_bytes) != (32 if key_type == 18 else 16):
        raise CredentialInputError("Keytab contains an invalid key length")
    logger.debug("Loaded one keytab identity and its newest supported key")
    return KerberosCredentials(
        account,
        selected_realm,
        "keytab",
        _aes_key=key_bytes if key_type in (17, 18) else b"",
        _nt_hash=key_bytes if key_type == 23 else b"",
    )


def load_kerberos_credentials(
    *,
    ticket: str | None = None,
    ccache_file: str | Path | None = None,
    keytab_file: str | Path | None = None,
    username: str | None = None,
    realm: str | None = None,
) -> KerberosCredentials:
    """Load a KRB-CRED, MIT ccache v3/v4, or MIT keytab v2 without environment edits."""
    validate_secret_sources(ticket=ticket, ccache=ccache_file, keytab=keytab_file)
    username, realm = _identity_hint(username, realm)
    try:
        if keytab_file is not None:
            return _load_keytab(keytab_file, username, realm)
        if ccache_file is not None:
            data = _read_file(ccache_file)
            if data[:2] not in (b"\x05\x03", b"\x05\x04"):
                raise CredentialInputError(
                    "Only MIT credential-cache versions 3 and 4 are supported"
                )
            cache = CCache(data)
            source = "credential cache"
        elif ticket is not None:
            if len(ticket) > (_MAX_INPUT_BYTES * 4 // 3 + 4):
                raise CredentialInputError(
                    "Kerberos credential inputs may not exceed 16 MiB"
                )
            cache = CCache()
            cache.fromKRBCRED(base64.b64decode(ticket, validate=True))
            source = "base64 ticket"
        else:
            raise CredentialInputError("Select a ticket, credential cache, or keytab")
        if cache.principal is None or not cache.credentials:
            raise CredentialInputError(
                "Supplied Kerberos credentials contain no identity or tickets"
            )
        account, selected_realm = _principal(
            cache.principal.prettyPrint().decode("utf-8")
        )
        if (username and account.casefold() != username.casefold()) or (
            realm and selected_realm != realm
        ):
            raise CredentialInputError(
                "Supplied Kerberos credentials do not match the selected username or realm"
            )
        expected = f"{account}@{selected_realm}".casefold()
        if any(
            credential["client"].prettyPrint().decode("utf-8").casefold() != expected
            for credential in cache.credentials
        ):
            raise CredentialInputError(
                "A credential cache must contain tickets for only its selected identity"
            )
        logger.debug("Loaded one explicit Kerberos identity from %s", source)
        return KerberosCredentials(account, selected_realm, source, _cache=cache)
    except CredentialInputError:
        logger.error("The selected Kerberos credential source is unusable")
        raise
    except Exception as error:
        # Provider parser messages may contain portions of the supplied bytes.
        logger.error("Kerberos credential parsing failed (%s)", type(error).__name__)
        raise CredentialInputError(
            "The selected Kerberos credential source could not be parsed"
        ) from None
