"""Explicit identities and exact service selection must never borrow OS cache state."""

import base64
import os
import socket
from concurrent.futures import ThreadPoolExecutor

import pytest
from impacket.krb5.ccache import CCache

from kerberos_fixtures import cache_bytes, keytab_bytes
from openhound_collector_common.clients import kerberos
from openhound_collector_common.clients.kerberos import (
    CredentialInputError,
    KerberosAcquisitionError,
    load_kerberos_credentials,
)
from openhound_collector_common.clients.wmi import WmiAuth


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail(
            "Credential-file checks must remain offline"
        ),
    )


@pytest.mark.parametrize("version", [3, 4])
def test_real_cache_formats_keep_principal_and_exact_port(tmp_path, version):
    path = tmp_path / "selected-cache"
    path.write_bytes(
        cache_bytes("MSSQLSvc/sql.example.com:51433@EXAMPLE.COM", version=version)
    )
    selected = load_kerberos_credentials(ccache_file=path)
    assert (selected.username, selected.realm) == ("first", "EXAMPLE.COM")
    assert selected.service_ticket("MSSQLSvc/sql.example.com:51433")["KDC_REP"]
    with pytest.raises(CredentialInputError, match="No matching service ticket"):
        selected.service_ticket("MSSQLSvc/sql.example.com:1433")


def test_base64_ticket_uses_its_identity_and_does_not_mutate_environment(monkeypatch):
    cache = CCache(cache_bytes("ldap/dc.example.com@EXAMPLE.COM"))
    monkeypatch.setenv("KRB5CCNAME", "another-users-cache")
    before = dict(os.environ)
    selected = load_kerberos_credentials(
        ticket=base64.b64encode(cache.toKRBCRED()).decode("ascii")
    )
    assert selected.service_ticket("ldap/dc.example.com")["KDC_REP"]
    assert os.environ == before


@pytest.mark.parametrize(
    "username,realm",
    [("second", None), (None, "OTHER.COM"), ("first@OTHER.COM", "EXAMPLE.COM")],
)
def test_file_identity_must_match_supplied_hints(tmp_path, username, realm):
    path = tmp_path / "cache"
    path.write_bytes(cache_bytes("ldap/dc.example.com@EXAMPLE.COM"))
    with pytest.raises(CredentialInputError):
        load_kerberos_credentials(ccache_file=path, username=username, realm=realm)


def test_expired_service_ticket_is_not_treated_as_a_tgt(tmp_path):
    path = tmp_path / "expired"
    path.write_bytes(cache_bytes("ldap/dc.example.com@EXAMPLE.COM", expired=True))
    selected = load_kerberos_credentials(ccache_file=path)
    with pytest.raises(CredentialInputError, match="No matching service ticket"):
        selected.service_ticket("ldap/dc.example.com")


def test_two_concurrent_sources_keep_their_own_service_identity(tmp_path):
    def select(username):
        path = tmp_path / username
        path.write_bytes(
            cache_bytes(
                "ldap/dc.example.com@EXAMPLE.COM", username=f"{username}@EXAMPLE.COM"
            )
        )
        selected = load_kerberos_credentials(ccache_file=path)
        return selected.username, selected.service_ticket("ldap/dc.example.com")[
            "KDC_REP"
        ]

    with ThreadPoolExecutor(max_workers=2) as workers:
        first, second = list(workers.map(select, ["first", "second"]))
    assert first[0] == "first" and second[0] == "second" and first[1] != second[1]


def test_keytab_prefers_newest_key_version_then_supported_encryption(tmp_path):
    path = tmp_path / "keys"
    path.write_bytes(
        keytab_bytes(
            ("first@EXAMPLE.COM", 18, 1, b"o" * 32),
            ("first@EXAMPLE.COM", 23, 2, b"r" * 16),
            ("first@EXAMPLE.COM", 17, 2, b"a" * 16),
            deleted_hole=True,
        )
    )
    selected = load_kerberos_credentials(keytab_file=path)
    assert selected._aes_key == b"a" * 16 and selected._nt_hash == b""


@pytest.mark.parametrize(
    "encryption,key", [(18, b"a" * 32), (17, b"b" * 16), (23, b"c" * 16)]
)
def test_supported_keytab_encryption_types(tmp_path, encryption, key):
    path = tmp_path / "keys"
    path.write_bytes(keytab_bytes(("first@EXAMPLE.COM", encryption, 7, key)))
    selected = load_kerberos_credentials(keytab_file=path)
    assert selected._aes_key == (key if encryption != 23 else b"")
    assert selected._nt_hash == (key if encryption == 23 else b"")


def test_keytab_zero_length_record_is_the_format_end_marker(tmp_path):
    path = tmp_path / "keys"
    path.write_bytes(
        keytab_bytes(("first@EXAMPLE.COM", 18, 1, b"a" * 32))
        + b"\x00" * 4
        + b"unused trailing space"
    )
    assert load_kerberos_credentials(keytab_file=path).username == "first"


def test_ambiguous_keytab_requires_identity_selection(tmp_path):
    path = tmp_path / "keys"
    path.write_bytes(
        keytab_bytes(
            ("first@EXAMPLE.COM", 18, 1, b"a" * 32),
            ("second@EXAMPLE.COM", 18, 1, b"b" * 32),
        )
    )
    with pytest.raises(CredentialInputError, match="ambiguous"):
        load_kerberos_credentials(keytab_file=path)
    assert (
        load_kerberos_credentials(keytab_file=path, username="second").username
        == "second"
    )


def test_failed_keytab_is_submitted_once_across_concurrent_consumers(
    tmp_path, monkeypatch
):
    path = tmp_path / "keys"
    path.write_bytes(keytab_bytes(("first@EXAMPLE.COM", 18, 1, b"a" * 32)))
    selected = load_kerberos_credentials(keytab_file=path)
    attempts = []

    def fail(*args):
        attempts.append(True)
        raise RuntimeError("raw provider response must not escape")

    monkeypatch.setattr(kerberos, "getKerberosTGT", fail)

    def request(_):
        with pytest.raises(KerberosAcquisitionError):
            selected.service_ticket("HOST/sql.example.com")

    with ThreadPoolExecutor(max_workers=3) as workers:
        list(workers.map(request, range(3)))
    assert attempts == [True]
    with pytest.raises(KerberosAcquisitionError):
        WmiAuth(kerberos_credentials=selected).kerberos_credentials.service_ticket("HOST/sql.example.com")


def test_reused_keytab_failure_still_says_the_password_was_refused(
    tmp_path, monkeypatch
):
    path = tmp_path / "keys"
    path.write_bytes(keytab_bytes(("first@EXAMPLE.COM", 18, 1, b"a" * 32)))
    selected = load_kerberos_credentials(keytab_file=path)

    class KdcReply(Exception):
        def getErrorCode(self):
            return 24  # KDC_ERR_PREAUTH_FAILED: the key or password was wrong

    def refuse(*args):
        raise KdcReply("raw provider response must not escape")

    monkeypatch.setattr(kerberos, "getKerberosTGT", refuse)
    for _ in range(2):  # The second call reuses the cached failure.
        with pytest.raises(KerberosAcquisitionError) as caught:
            selected.service_ticket("HOST/sql.example.com")
        assert caught.value.is_rejected_identity


def test_wmi_retains_validated_credentials_even_if_cache_file_is_replaced(tmp_path):
    path = tmp_path / "cache"
    path.write_bytes(cache_bytes("HOST/sql.example.com@EXAMPLE.COM"))
    selected = load_kerberos_credentials(ccache_file=path)
    path.write_bytes(b"file replaced after validation")
    auth = WmiAuth(kerberos_credentials=selected)
    assert auth.kerberos_credentials.username == "first"
    assert auth.kerberos_credentials.service_ticket("HOST/sql.example.com")["KDC_REP"]


@pytest.mark.parametrize("payload", [b"", b"\x05\x01", b"\x05\x04broken"])
def test_malformed_files_do_not_echo_path_or_bytes(tmp_path, payload):
    path = tmp_path / "private-secret-file"
    path.write_bytes(payload)
    with pytest.raises(CredentialInputError) as error:
        load_kerberos_credentials(ccache_file=path)
    assert str(path) not in str(error.value)
    assert "broken" not in str(error.value)


def test_competing_secret_families_are_rejected_before_parsing(tmp_path):
    with pytest.raises(CredentialInputError, match="Choose only one"):
        load_kerberos_credentials(ticket="secret", ccache_file=tmp_path / "absent")
