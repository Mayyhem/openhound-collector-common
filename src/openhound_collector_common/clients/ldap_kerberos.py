"""Connection-local Kerberos bind and LDAP sealing using the installed providers.

ldap3 keeps its normal socket setup, port selection, paging and Entry objects.
Impacket supplies the Kerberos ticket and GSS encryption. This avoids relying
on an OS cache selection that Windows' integrated provider does not support.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from impacket.krb5.gssapi import (
    GSSAPI,
    GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
)
from ldap3 import SASL, Connection
from ldap3.core.exceptions import LDAPBindError
from ldap3.operation.bind import bind_operation

from ..logging import get_logger
from ..logging.authentication import authentication_diagnostics
from .auth import KerberosToken
from .kerberos import KerberosCredentials, TicketMaterial

logger = get_logger(__name__)
_MAX_SEALED_PACKET = 16 * 1024 * 1024


def _tls_binding(raw_socket: socket.socket) -> bytes:
    """Hash this TLS endpoint using RFC 5929 and the GSS channel-binding format."""
    # The caller reaches this helper only after ldap3 opened SSL/StartTLS.
    certificate = raw_socket.getpeercert(binary_form=True)  # type: ignore[attr-defined]
    parsed = x509.load_der_x509_certificate(certificate)
    algorithm = parsed.signature_hash_algorithm
    if algorithm is None:
        logger.warning("LDAP certificate has no supported channel-binding hash")
        raise LDAPBindError("Cannot derive channel binding for this LDAP certificate")
    if algorithm.name in ("md5", "sha1"):
        # RFC 5929 replaces these weak certificate hashes with SHA-256.
        algorithm = hashes.SHA256()
    digest = hashes.Hash(algorithm)
    digest.update(certificate)
    application = b"tls-server-end-point:" + digest.finalize()
    binding = b"\x00" * 16 + struct.pack("<I", len(application)) + application
    # MD5 is required by the GSS channel-binding wire format; it is not being
    # chosen as the certificate's signature or a password hash.
    return hashlib.md5(binding, usedforsecurity=False).digest()


class KerberosLdapSocket:
    """Seal complete LDAP requests and expose verified replies as ordinary bytes.

    One ldap3 connection serializes its requests with its existing lock. The
    wrapper keeps receive buffering local and delegates socket lifetime/timeout
    operations to that connection's original socket, including SOCKS sockets.
    """

    def __init__(self, raw_socket: socket.socket, material: TicketMaterial) -> None:
        self._socket = raw_socket
        self._gss = GSSAPI(material["cipher"])
        self._key = material["sessionKey"]
        self._sequence = 0
        self._received = bytearray()

    def __getattr__(self, name: str) -> Any:
        # ldap3/socket implementations expose additional platform-specific
        # methods. This is a narrow transport bridge, not graph/config data.
        return getattr(self._socket, name)

    def sendall(self, data: bytes) -> None:
        """Send one sealed LDAP message with its standard four-byte length."""
        sealed, signature = self._gss.GSS_Wrap_LDAP(self._key, data, self._sequence)
        self._sequence += 1
        packet = signature + sealed
        if len(packet) > _MAX_SEALED_PACKET:
            logger.error("Sealed LDAP request exceeds the packet limit")
            raise OSError("Sealed LDAP request exceeds 16 MiB")
        self._socket.sendall(struct.pack(">I", len(packet)) + packet)

    def _read_exact(self, count: int, *, allow_eof: bool = False) -> bytes:
        data = bytearray()
        while len(data) < count:
            part = self._socket.recv(count - len(data))
            if not part:
                if allow_eof and not data:
                    # End of an idle connection is an ordinary socket EOF.
                    return b""
                logger.warning("LDAP connection ended inside a sealed packet")
                raise OSError("LDAP connection ended inside a sealed packet")
            data.extend(part)
        return bytes(data)

    def recv(self, count: int) -> bytes:
        """Return up to count decoded bytes, retaining the remainder of a reply."""
        if count <= 0:
            # Match the normal zero-byte socket-read contract.
            return b""
        if not self._received:
            header = self._read_exact(4, allow_eof=True)
            if not header:
                return b""  # The caller handles the ordinary socket EOF.
            length = struct.unpack(">I", header)[0]
            if not 0 < length <= _MAX_SEALED_PACKET:
                logger.error("LDAP peer supplied an invalid sealed packet length")
                raise OSError("Invalid sealed LDAP packet length")
            packet = self._read_exact(length)
            plain, _ = self._gss.GSS_Unwrap_LDAP(self._key, packet, 0, direction="init")
            self._received.extend(plain)
        result = bytes(self._received[:count])
        del self._received[:count]
        return result


def bind_explicit_kerberos(
    connection: Connection,
    *,
    host: str,
    realm: str,
    username: str | None,
    password: str | None,
    nt_hash: str | None,
    credentials: KerberosCredentials | None,
    kdc_host: str | None,
    use_tls: bool,
) -> None:
    """Bind an already opened ldap3 connection using this identity only.

    GSS-SPNEGO, checksum flags and LDAP sealing follow impacket 0.13.1's LDAP
    implementation. ldap3's ordinary current-user GSSAPI path stays separate.
    """
    flags = GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG
    if not use_tls:
        flags |= GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
    # TLS protects query data itself; plain LDAP uses GSS confidentiality.
    token = KerberosToken(
        spn=f"ldap/{host}",
        realm=realm,
        username=username,
        password=password,
        nt_hash=nt_hash,
        credentials=credentials,
        kdc_host=kdc_host,
        gss_flags=flags,
        mutual_auth=False,
        channel_binding=_tls_binding(connection.socket) if use_tls else None,
    )
    with connection.connection_lock, authentication_diagnostics():
        connection.sasl_in_progress = True
        try:
            request = bind_operation(
                connection.version,
                SASL,
                "",
                None,
                "GSS-SPNEGO",
                token.ap_req_spnego(),
            )
            response = connection.post_send_single_response(
                connection.send("bindRequest", request, None)
            )
            result = response[0]
            connection.result = result
            connection.bound = bool(result and result.get("result") == 0)
            if not connection.bound:
                logger.error("LDAP rejected the selected Kerberos identity")
                # Preserve AD's safe result-49 diagnostic (for example data
                # 52e) so credential rejection stops the transport fallback.
                # Do not include the complete result: it can carry SASL bytes.
                raise LDAPBindError(
                    f"{result.get('description') or 'Kerberos bind failed'}: {result.get('message') or ''}"
                )
            if not use_tls:
                connection.socket = KerberosLdapSocket(
                    connection.socket, token.service_material()
                )  # type: ignore[assignment]
            # This wrapper owns GSS framing. ldap3 must not wrap the same packet again.
            # types-ldap3 2.9 lacks this field, added by our pinned 2.10.2rc4.
            connection.session_security = None  # type: ignore[attr-defined]
        finally:
            connection.sasl_in_progress = False
