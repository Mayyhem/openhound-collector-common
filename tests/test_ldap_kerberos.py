"""Check LDAP framing, authenticated encryption and certificate channel binding."""

import datetime
import hashlib
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from impacket.krb5.crypto import Key, _AES256CTS, InvalidChecksum
from impacket.krb5.gssapi import GSSAPI, KG_USAGE_ACCEPTOR_SEAL

from openhound_collector_common.clients.ldap_kerberos import (
    KerberosLdapSocket,
    _tls_binding,
)


class Socket:
    def __init__(self, incoming=b""):
        self.incoming = bytearray(incoming)
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, count):
        # Force fragmented headers and payloads to exercise ordinary TCP reads.
        part = bytes(self.incoming[: min(count, 3)])
        del self.incoming[: len(part)]
        return part

    def gettimeout(self):
        return 7


def material():
    return {"KDC_REP": b"", "cipher": _AES256CTS(), "sessionKey": Key(18, b"x" * 32)}


def reply_packet(data):
    """Create one synthetic acceptor reply using the provider's encryption."""
    value = material()
    gss = GSSAPI(value["cipher"])
    header = gss.WRAP()
    header["Flags"] = 7
    header["SND_SEQ"] = struct.pack(">Q", 0)
    encrypted = value["cipher"].encrypt(
        value["sessionKey"], KG_USAGE_ACCEPTOR_SEAL, data + header.getData(), None
    )
    header["RRC"] = 28
    packet = header.getData() + gss.rotate(encrypted, 28)
    return struct.pack(">I", len(packet)) + packet


def test_fragmented_encrypted_reply_is_verified_and_buffered():
    raw = Socket(reply_packet(b"complete LDAP message"))
    wrapped = KerberosLdapSocket(raw, material())
    assert wrapped.recv(5) == b"compl"
    assert wrapped.recv(100) == b"ete LDAP message"
    assert wrapped.recv(100) == b""
    assert wrapped.gettimeout() == 7


def test_modified_encrypted_reply_does_not_return_plaintext():
    packet = bytearray(reply_packet(b"complete LDAP message"))
    packet[-1] ^= 1
    with pytest.raises(InvalidChecksum):
        KerberosLdapSocket(Socket(packet), material()).recv(100)


def test_requests_have_bounded_frames_and_increasing_sequence_numbers():
    raw = Socket()
    wrapped = KerberosLdapSocket(raw, material())
    wrapped.sendall(b"one request")
    wrapped.sendall(b"another request")
    assert [struct.unpack(">Q", packet[12:20])[0] for packet in raw.sent] == [0, 1]
    assert all(
        struct.unpack(">I", packet[:4])[0] == len(packet) - 4 for packet in raw.sent
    )


@pytest.mark.parametrize(
    "incoming",
    [
        b"\x00",
        struct.pack(">I", 20) + b"short",
        struct.pack(">I", 0),
        struct.pack(">I", 16 * 1024 * 1024 + 1),
    ],
)
def test_truncated_or_oversized_reply_is_an_explicit_failure(incoming):
    with pytest.raises(OSError):
        KerberosLdapSocket(Socket(incoming), material()).recv(100)


def test_tls_channel_binding_uses_the_actual_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "offline.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    encoded = cert.public_bytes(serialization.Encoding.DER)

    class TlsSocket:
        def getpeercert(self, binary_form):
            assert binary_form
            return encoded

    application = b"tls-server-end-point:" + hashlib.sha256(encoded).digest()
    expected = hashlib.md5(
        b"\x00" * 16 + struct.pack("<I", len(application)) + application,
        usedforsecurity=False,
    ).digest()
    assert _tls_binding(TlsSocket()) == expected
