"""Build synthetic MIT files with real provider encoders and no usable secrets."""

import struct
import time

from impacket.krb5.asn1 import Ticket, seq_set
from impacket.krb5.ccache import (
    CCache,
    Credential,
    CountedOctetString,
    KeyBlockV3,
    KeyBlockV4,
    Principal as CachePrincipal,
    Times,
)
from impacket.krb5.types import Principal
from pyasn1.codec.der import encoder


def principal(name):
    value = CachePrincipal()
    value.fromPrincipal(Principal(name, type=1))
    return value


def cache_bytes(*services, username="first@EXAMPLE.COM", expired=False, version=4):
    cache = CCache()
    cache.setDefaultHeader()
    cache.principal = principal(username)
    for service in services:
        server, realm = service.rsplit("@", 1)
        ticket = Ticket()
        ticket["tkt-vno"] = 5
        ticket["realm"] = realm
        seq_set(ticket, "sname", Principal(server, type=2).components_to_asn1)
        ticket["enc-part"]["etype"] = 18
        ticket["enc-part"]["cipher"] = b"synthetic-unusable-encrypted-ticket"
        credential = Credential()
        if version == 3:
            credential.header = Credential.CredentialHeaderV3()
        credential["client"] = principal(username)
        credential["server"] = principal(service)
        credential["key"] = KeyBlockV3() if version == 3 else KeyBlockV4()
        credential["key"]["keytype"] = 18
        if version == 3:
            credential["key"]["etype"] = 18  # MIT v3 repeats the encryption type.
        credential["key"]["keylen"] = 32
        credential["key"]["keyvalue"] = b"x" * 32
        credential["time"] = Times()
        for name in ("authtime", "starttime", "endtime", "renew_till"):
            credential["time"][name] = int(time.time()) + (-3600 if expired else 3600)
        credential["is_skey"] = 0
        credential["tktflags"] = 0
        credential["num_address"] = 0
        credential.ticket = CountedOctetString()
        credential.ticket["length"] = len(encoder.encode(ticket))
        credential.ticket["data"] = encoder.encode(ticket)
        credential.secondTicket = CountedOctetString()
        credential.secondTicket["length"] = 0
        credential.secondTicket["data"] = b""
        cache.credentials.append(credential)
    if version == 3:
        return (
            b"\x05\x03"
            + cache.principal.getData()
            + b"".join(row.getData() for row in cache.credentials)
        )
    return cache.getData()


def keytab_bytes(*entries, deleted_hole=False):
    """Entries contain (principal, encryption type, key version, key bytes)."""

    def counted(value):
        value = value.encode("utf-8")
        return struct.pack(">H", len(value)) + value

    data = bytearray(b"\x05\x02")
    if deleted_hole:
        data.extend(struct.pack(">i", -5) + b"holes")
    for name, encryption, version, key in entries:
        username, realm = name.rsplit("@", 1)
        components = username.split("/")
        entry = struct.pack(">H", len(components)) + counted(realm)
        entry += b"".join(counted(component) for component in components)
        entry += struct.pack(">IIBHH", 1, 0, version % 256, encryption, len(key)) + key
        entry += struct.pack(">I", version)
        data.extend(struct.pack(">i", len(entry)) + entry)
    return bytes(data)
