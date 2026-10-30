"""Pinned Go/MS-NLMP vectors and real shared NTLM token-builder contracts.

Crypto remains delegated to impacket 0.13.1. Fixed public vectors are test data,
not actual credentials. No target or network connection is used.
"""

import hmac
import struct
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from types import SimpleNamespace

import pytest
from Cryptodome.Cipher import ARC4
from impacket import ntlm, tds

from openhound_collector_common.clients import auth, mssql


def challenge_message(*, has_key_exchange=True, has_timestamp=True):
    """Supply the Go minimal challenge plus DNS data required by this provider."""
    fields = ntlm.AV_PAIRS()
    fields[ntlm.NTLMSSP_AV_DOMAINNAME] = "Domain".encode("utf-16le")
    fields[ntlm.NTLMSSP_AV_HOSTNAME] = "Server".encode("utf-16le")
    fields[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = "server.example.test".encode("utf-16le")
    if has_timestamp:
        fields[ntlm.NTLMSSP_AV_TIME] = bytes.fromhex("0090d336b734c301")
    fields[ntlm.NTLMSSP_AV_FLAGS] = struct.pack("<I", 2)
    # Unknown fields must survive an unrelated service-name omission as well.
    fields[4096] = b"opaque server field"
    domain = "Domain".encode("utf-16le")
    challenge = ntlm.NTLMAuthChallenge()
    challenge["flags"] = 0xA2898205
    if has_key_exchange:
        challenge["flags"] |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
    else:
        challenge["flags"] &= ~ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
    challenge["challenge"] = bytes.fromhex("0123456789abcdef")
    challenge["reserved"] = b"\x00" * 8
    challenge["Version"] = struct.pack("<BBH3sB", 10, 0, 20348, b"\x00" * 3, 15)
    challenge["domain_name"] = domain
    challenge["domain_offset"] = 56
    challenge["TargetInfoFields"] = fields.getData()
    challenge["TargetInfoFields_offset"] = 56 + len(domain)
    return challenge.getData()


def client_version():
    """Use the version advertised by the real shared SQL EPA login path."""
    version = ntlm.VERSION()
    (
        version["ProductMajorVersion"],
        version["ProductMinorVersion"],
        version["ProductBuild"],
    ) = 10, 0, 20348
    return version


def test_go_ntlmv2_hash_vector_at_the_used_provider_boundary():
    assert (
        ntlm.NTOWFv2("User", "Password", "Domain").hex()
        == "0c868a403bfd7a93a3001ef22ef02e3f"
    )


def test_go_nt_proof_vector_and_session_key_contract():
    key = ntlm.NTOWFv2("User", "Password", "Domain")
    server_challenge = bytes.fromhex("0123456789abcdef")
    target_info = bytes.fromhex(
        "02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000"
    )
    blob = b"\x01\x01" + b"\x00" * 6
    blob += bytes.fromhex("0090d336b734c301") + bytes.fromhex("aaaaaaaaaaaaaaaa")
    blob += b"\x00" * 4 + target_info + b"\x00" * 4
    proof = auth.hmac_md5(key, server_challenge + blob)
    assert proof.hex() == "8c5ecac7a1148dd21ff304095861181e"
    session_key = auth.hmac_md5(key, proof)
    assert len(session_key) == 16
    messages = b"".join(b"NTLMSSP\x00" + struct.pack("<I", kind) for kind in (1, 2, 3))
    assert auth.hmac_md5(session_key, messages) == auth.hmac_md5(session_key, messages)


def test_go_integrity_check_contract_on_the_actual_shared_token():
    version = client_version()
    first = auth.ntlm_type1(version=version)
    challenge = challenge_message()
    third, session_key = auth.ntlm_type3(
        type1=first,
        server_challenge=challenge,
        username="User",
        password="Password",
        domain="Domain",
        version=version,
    )
    mic = third["MIC"]
    assert len(mic) == len(session_key) == 16
    received = ntlm.NTLMAuthChallengeResponse()
    received.fromString(third.getData())
    assert received["MIC"] == mic
    third["MIC"] = b"\x00" * 16
    assert mic == ntlm.hmac_md5(
        session_key, first.getData() + challenge + third.getData()
    )


def test_go_tls_unique_binding_hash_contract_uses_the_real_sql_provider():
    value = b"test tls finished message data"
    connection = SimpleNamespace(tls_unique=value)
    first = mssql._Tds.generate_cbt_from_tls_unique(connection)
    second = mssql._Tds.generate_cbt_from_tls_unique(connection)
    assert len(first) == 16 and first == second
    different = mssql._Tds.generate_cbt_from_tls_unique(
        SimpleNamespace(tls_unique=value + b"different")
    )
    assert first != different


def test_go_full_exchange_contract_preserves_service_and_channel_binding():
    version = client_version()
    first = auth.ntlm_type1(version=version)
    challenge = challenge_message()
    binding = bytes.fromhex("00112233445566778899aabbccddeeff")
    third, session_key = auth.ntlm_type3(
        type1=first,
        server_challenge=challenge,
        username="User",
        password="Password",
        domain="Domain",
        channel_binding_value=binding,
        version=version,
    )
    assert first.getData().startswith(b"NTLMSSP\x00\x01\x00\x00\x00")
    assert third.getData().startswith(b"NTLMSSP\x00\x03\x00\x00\x00")
    pairs = ntlm.AV_PAIRS(third["ntlm"][44:])
    assert (
        pairs[ntlm.NTLMSSP_AV_TARGET_NAME][1].decode("utf-16le")
        == "MSSQLSvc/server.example.test"
    )
    assert pairs[ntlm.NTLMSSP_AV_CHANNEL_BINDINGS][1] == binding
    assert len(session_key) == 16 and len(third["MIC"]) == 16


@pytest.mark.parametrize(
    "username,domain",
    [
        ("Password", "MAYYHEM"),
        ("USERDomain", "mayyhem"),
        ("DOMAINADMINMAYYHEM", "MAYYHEM"),
        ("User", "Domain"),
    ],
)
def test_go_utf16_account_fields_use_the_shared_authenticate_message(username, domain):
    version = client_version()
    first = auth.ntlm_type1(version=version)
    third, _ = auth.ntlm_type3(
        type1=first,
        server_challenge=challenge_message(),
        username=username,
        password="Password",
        domain=domain,
        version=version,
    )
    assert third["user_name"] == username.encode("utf-16le")
    assert third["domain_name"] == domain.encode("utf-16le")


@pytest.mark.parametrize("compute_mic", [False, True])
def test_ordinary_authenticate_message_matches_the_unmodified_provider(
    monkeypatch, compute_mic
):
    monkeypatch.setattr(ntlm.random, "choice", lambda _: "a")
    version = client_version()
    first = auth.ntlm_type1(version=version)
    challenge = challenge_message()
    arguments = dict(
        type1=first,
        server_challenge=challenge,
        username="User",
        password="Password",
        domain="Domain",
        channel_binding_value=b"c" * 16,
        version=version,
    )
    expected, expected_key = ntlm.getNTLMSSPType3(
        first,
        challenge,
        "User",
        "Password",
        "Domain",
        service=auth.DEFAULT_SERVICE_CLASS,
        channel_binding_value=b"c" * 16,
        version=version,
    )
    if compute_mic:
        expected["MIC"] = b"\x00" * 16
        expected["MIC"] = hmac.digest(
            expected_key, first.getData() + challenge + expected.getData(), "md5"
        )
    actual, actual_key = auth.ntlm_type3(**arguments, compute_mic=compute_mic)
    assert actual.getData() == expected.getData()
    assert actual_key == expected_key


@pytest.mark.parametrize("has_key_exchange", [False, True])
@pytest.mark.parametrize("has_timestamp", [False, True])
@pytest.mark.parametrize("binding", [b"", b"c" * 16])
def test_missing_service_preserves_other_fields_and_updates_proof_keys_and_mic(
    monkeypatch, has_key_exchange, has_timestamp, binding
):
    # Fix provider randomness/time only inside this offline test, so two messages
    # differ solely in the one requested service-name omission.
    monkeypatch.setattr(ntlm.random, "choice", lambda _: "a")
    monkeypatch.setattr(ntlm.calendar, "timegm", lambda _: 1000000000)
    version = client_version()
    first = auth.ntlm_type1(version=version)
    challenge = challenge_message(
        has_key_exchange=has_key_exchange, has_timestamp=has_timestamp
    )
    arguments = dict(
        type1=first,
        server_challenge=challenge,
        username="User",
        password="Password",
        domain="Domain",
        channel_binding_value=binding,
        version=version,
    )
    ordinary, ordinary_key = auth.ntlm_type3(**arguments)
    probe, probe_key = auth.ntlm_type3(**arguments, omit_target_service=True)
    ordinary_fields = ntlm.AV_PAIRS(ordinary["ntlm"][44:])
    probe_fields = ntlm.AV_PAIRS(probe["ntlm"][44:])
    assert ordinary_fields[ntlm.NTLMSSP_AV_TARGET_NAME] is not None
    assert probe_fields[ntlm.NTLMSSP_AV_TARGET_NAME] is None
    del ordinary_fields[ntlm.NTLMSSP_AV_TARGET_NAME]
    assert probe_fields.fields == ordinary_fields.fields
    assert probe["ntlm"][16:44] == ordinary["ntlm"][16:44]
    assert probe["ntlm"][24:32] != b"\x00" * 8  # Timestamp was never zeroed.
    assert probe["lanman"] == ordinary["lanman"]
    for field in ("flags", "user_name", "domain_name", "host_name", "Version"):
        assert probe[field] == ordinary[field]

    # Independently verify the final response through the documented NTLMv2
    # formula, then decrypt the exchanged key as the receiving server would.
    response_key = hmac.digest(
        ntlm.compute_nthash("Password"), "USERDomain".encode("utf-16le"), "md5"
    )
    server_nonce = ntlm.NTLMAuthChallenge(challenge)["challenge"]
    expected_proof = hmac.digest(response_key, server_nonce + probe["ntlm"][16:], "md5")
    assert probe["ntlm"][:16] == expected_proof
    session_base_key = hmac.digest(response_key, expected_proof, "md5")
    if has_key_exchange:
        assert ARC4.new(session_base_key).decrypt(probe["session_key"]) == probe_key
        assert probe_key == ordinary_key == b"a" * 16
    else:
        assert probe_key == session_base_key
        assert probe_key != ordinary_key
        assert not probe["session_key"]

    received = ntlm.NTLMAuthChallengeResponse()
    received.fromString(probe.getData())
    mic = received["MIC"]
    probe["MIC"] = b"\x00" * 16
    assert mic == hmac.digest(
        probe_key, first.getData() + challenge + probe.getData(), "md5"
    )
    assert ntlm.TEST_CASE is False


class OfflineSqlTransport:
    """Replace only the network; run the real EPA login and NTLM builders."""

    tds8 = False

    def __init__(self):
        self.sent_messages = {}

    def _negotiate_encryption(self):
        return {"Encryption": mssql.ENCRYPT_OFF}

    def _build_login7(self, *args, **kwargs):
        return SimpleNamespace(getData=lambda: b"offline LOGIN7 placeholder")

    def sendTDS(self, kind, data):
        self.sent_messages[kind] = data

    def recvTDS(self):
        return {"Data": b"\x00" * 3 + challenge_message()}

    def _has_active_tls_channel_binding(self):
        return False

    def parseReply(self, data):
        return {tds.TDS_LOGINACK_TOKEN: True}


@pytest.mark.parametrize("should_probe_fail", [False, True])
def test_concurrent_probe_cannot_change_other_logins_or_leave_a_global_flag(
    monkeypatch, should_probe_fail
):
    probe_entered, ordinary_built, probe_finished = Event(), Event(), Event()
    observed_flags = []
    provider = auth.getNTLMSSPType3

    def interleaved_provider(*args, **kwargs):
        # Force the interleaving which previously leaked TEST_CASE=True. The
        # unrelated direct provider call deliberately bypasses common's helper.
        if args[2] == "Probe":
            observed_flags.append(ntlm.TEST_CASE)
            probe_entered.set()
            assert ordinary_built.wait(5)
            if should_probe_fail:
                raise RuntimeError("controlled provider failure")
            return provider(*args, **kwargs)
        assert probe_entered.wait(5)
        observed_flags.append(ntlm.TEST_CASE)
        result = provider(*args, **kwargs)
        ordinary_built.set()
        assert probe_finished.wait(5)
        return result

    def run_probe():
        try:
            return mssql._Tds.login_epa(
                probe_transport,
                database=None,
                username="Probe",
                password="Password",
                domain="Domain",
                strip_target_service=True,
            )
        finally:
            probe_finished.set()

    probe_transport, ordinary_transport = OfflineSqlTransport(), OfflineSqlTransport()
    monkeypatch.setattr(auth, "getNTLMSSPType3", interleaved_provider)
    assert ntlm.TEST_CASE is False
    with ThreadPoolExecutor(max_workers=2) as workers:
        probe_future = workers.submit(run_probe)
        assert probe_entered.wait(5)
        # A consumer outside common also sees the normal provider setting while
        # the missing-service SQL probe is still inside its authentication call.
        direct, _ = provider(
            auth.ntlm_type1(version=client_version()),
            challenge_message(),
            "Unrelated",
            "Password",
            "Domain",
            version=client_version(),
        )
        observed_flags.append(ntlm.TEST_CASE)
        ordinary_future = workers.submit(
            mssql._Tds.login_epa,
            ordinary_transport,
            database=None,
            username="Ordinary",
            password="Password",
            domain="Domain",
        )
        if should_probe_fail:
            with pytest.raises(RuntimeError, match="controlled provider failure"):
                probe_future.result(10)
        else:
            assert probe_future.result(10)
        assert ordinary_future.result(10)

    assert observed_flags == [False, False, False]
    assert ntlm.TEST_CASE is False
    ordinary = ntlm.NTLMAuthChallengeResponse()
    ordinary.fromString(ordinary_transport.sent_messages[tds.TDS_SSPI])
    for message in (ordinary, direct):
        assert ntlm.AV_PAIRS(message["ntlm"][44:])[ntlm.NTLMSSP_AV_TARGET_NAME]
    if not should_probe_fail:
        probe = ntlm.NTLMAuthChallengeResponse()
        probe.fromString(probe_transport.sent_messages[tds.TDS_SSPI])
        assert ntlm.AV_PAIRS(probe["ntlm"][44:])[ntlm.NTLMSSP_AV_TARGET_NAME] is None


def test_missing_service_does_not_reset_an_existing_provider_test_setting(monkeypatch):
    monkeypatch.setattr(ntlm, "TEST_CASE", True)
    assert mssql._Tds.login_epa(
        OfflineSqlTransport(),
        database=None,
        username="User",
        password="Password",
        strip_target_service=True,
    )
    assert ntlm.TEST_CASE is True


def test_missing_service_rejects_anonymous_non_ntlmv2_response():
    with pytest.raises(ValueError, match="requires an NTLMv2 response"):
        auth.ntlm_type3(
            type1=auth.ntlm_type1(version=client_version()),
            server_challenge=challenge_message(),
            username="",
            omit_target_service=True,
            version=client_version(),
        )
    assert ntlm.TEST_CASE is False


def test_missing_service_rejects_unrecognized_provider_trailing_bytes(monkeypatch):
    provider = auth.getNTLMSSPType3

    def changed_layout(*args, **kwargs):
        message, key = provider(*args, **kwargs)
        message["ntlm"] += b"unrecognized trailer"
        return message, key

    monkeypatch.setattr(auth, "getNTLMSSPType3", changed_layout)
    with pytest.raises(ValueError, match="Unsupported NTLMv2 field layout"):
        auth.ntlm_type3(
            type1=auth.ntlm_type1(version=client_version()),
            server_challenge=challenge_message(),
            username="User",
            password="Password",
            omit_target_service=True,
            version=client_version(),
        )
    assert ntlm.TEST_CASE is False


@pytest.mark.parametrize("hash_form", ["bare", "lm_nt"])
@pytest.mark.parametrize("omit_target_service", [False, True])
@pytest.mark.parametrize("has_key_exchange", [False, True])
def test_hash_forms_match_password_messages_without_changing_kerberos_text(
    monkeypatch, hash_form, omit_target_service, has_key_exchange
):
    monkeypatch.setattr(ntlm.random, "choice", lambda _: "a")
    version = client_version()
    arguments = dict(
        type1=auth.ntlm_type1(version=version),
        server_challenge=challenge_message(has_key_exchange=has_key_exchange),
        username="User",
        domain="Domain",
        omit_target_service=omit_target_service,
        channel_binding_value=b"c" * 16,
        version=version,
    )
    password_message, password_key = auth.ntlm_type3(**arguments, password="Password")
    nt_hash = ntlm.compute_nthash("Password").hex()
    hash_value = nt_hash if hash_form == "bare" else f"{auth.EMPTY_LM_HASH}:{nt_hash}"
    hash_message, hash_key = auth.ntlm_type3(**arguments, nt_hash=hash_value)
    assert hash_message.getData() == password_message.getData()
    assert hash_key == password_key
    assert auth.split_hashes(hash_value) == (auth.EMPTY_LM_HASH, nt_hash)
    assert all(isinstance(part, str) for part in auth.split_hashes(hash_value))


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "private-invalid-hex",
        "ab" * 15,
        "ab" * 17,
        f"{auth.EMPTY_LM_HASH}:",
        f"private-invalid-lm:{'ab' * 16}",
    ],
)
def test_invalid_hash_errors_do_not_reveal_the_supplied_value(caplog, invalid_hash):
    with pytest.raises(ValueError, match="NTLM hash") as failure:
        auth.ntlm_type3(
            type1=auth.ntlm_type1(version=client_version()),
            server_challenge=challenge_message(),
            username="User",
            nt_hash=invalid_hash,
            version=client_version(),
        )
    assert invalid_hash not in str(failure.value)
    assert invalid_hash not in caplog.text
    assert ntlm.TEST_CASE is False
