"""Rejected accounts stop actual bind retries without blocking transport recovery."""

from __future__ import annotations

import json
import socket
from types import SimpleNamespace

import pytest
from ldap3.core.exceptions import LDAPBindError

from openhound_collector_common.clients import ad
from openhound_collector_common.clients.operations import ReadControl


GO_BAD_PASSWORD = 'LDAP Result Code 49 "Invalid Credentials": data 52e'
GO_CHANNEL_BINDING = (
    'LDAP Result Code 49 "Invalid Credentials": 80090346: LdapErr: '
    "DSID-0C0906B0, comment: AcceptSecurityContext error, data 80090346, v4f7c"
)
EXAMPLE_PASSWORD = "illustrative-password-must-not-appear-in-reports"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail(
            "An offline rejection check attempted a network lookup or connection"
        )

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def selected_client(monkeypatch, *, controlled_reads=True):
    """Use real bind planning and loops; replace only discovery and the provider."""
    outcomes = []
    client = ad.AdClient(
        "example.test",
        dc="dc.example.test",
        auth=ad.LdapAuth(username="EXAMPLE\\reader", password=EXAMPLE_PASSWORD),
        read_control=ReadControl(2) if controlled_reads else None,
        on_query=outcomes.append,
    )
    monkeypatch.setattr(
        client,
        "_prepare_attempts_and_host",
        lambda attempts: (attempts, "dc.example.test"),
    )
    return client, outcomes


def rejected_provider(monkeypatch, client, failure):
    calls = []

    def open_connection(*, host, attempt):
        calls.append(attempt.label)
        raise failure

    monkeypatch.setattr(client, "_open_connection", open_connection)
    return calls


def test_go_bad_password_reply_stops_all_further_submissions(monkeypatch, caplog):
    client, outcomes = selected_client(monkeypatch)
    failure = LDAPBindError(GO_BAD_PASSWORD)
    calls = rejected_provider(monkeypatch, client, failure)
    assert len(client._build_attempt_plan()) > 1
    for _ in range(2):
        with pytest.raises(LDAPBindError) as caught:
            client.bind()
        assert caught.value is failure
    for _ in range(2):
        with pytest.raises(LDAPBindError) as caught:
            list(client.paged_search("(objectClass=computer)", ["name"]))
        assert caught.value is failure
    assert len(calls) == 1
    assert client._credential_failure is failure
    assert client._conn is None and client._opening_conn is None
    assert client._bind_operation is None
    assert len(outcomes) == 2
    assert all(
        result.state == "failed" and result.row_count is None for result in outcomes
    )
    recorded = json.dumps([result.as_row() for result in outcomes])
    assert EXAMPLE_PASSWORD not in recorded + caplog.text
    assert GO_BAD_PASSWORD not in recorded


def test_go_channel_binding_reply_still_allows_next_profile(monkeypatch):
    client, _ = selected_client(monkeypatch)
    failure = LDAPBindError(GO_CHANNEL_BINDING)
    calls = []
    connection = SimpleNamespace(bound=True, unbind=lambda: None)

    def open_connection(*, host, attempt):
        calls.append(attempt.label)
        if len(calls) == 1:
            raise failure
        return connection

    monkeypatch.setattr(client, "_open_connection", open_connection)
    try:
        assert client.bind() is connection
        assert client.bind() is connection  # A bound client is reused, not retried.
        assert len(calls) == 2
        assert client._credential_failure is None
        assert client._bind_operation is None
    finally:
        client.close()


@pytest.mark.parametrize("controlled_reads", [False, True])
@pytest.mark.parametrize(
    "label", ["invalidCredentials", "Invalid Credentials", "INVALID\tCREDENTIALS"]
)
@pytest.mark.parametrize("subcode", ["52e", "532", "533", "701", "773", "775"])
def test_known_rejected_accounts_stop_for_both_client_timeout_policies(
    monkeypatch, controlled_reads, label, subcode
):
    client, _ = selected_client(monkeypatch, controlled_reads=controlled_reads)
    failure = LDAPBindError(f"{label}: data {subcode}, v1")
    calls = rejected_provider(monkeypatch, client, failure)
    for _ in range(2):
        with pytest.raises(LDAPBindError):
            client.bind()
    assert len(calls) == 1
    assert client._credential_failure is failure


@pytest.mark.parametrize(
    "message",
    [
        "strongerAuthRequired",
        "Invalid Credentials: data 80090346",
        "Invalid Credentials: data 1234",
        # A bare "Invalid Credentials" with no reason used to retry here. Since
        # October 30, 2026 a typed-in identity stops on it instead; see
        # test_credential_guard.py. The lab showed that reply was a wrong password.
        "an unrelated message containing data 52e",
    ],
)
def test_other_replies_keep_existing_permitted_retries(monkeypatch, message):
    client, _ = selected_client(monkeypatch)
    failure = LDAPBindError(message)
    calls = rejected_provider(monkeypatch, client, failure)
    with pytest.raises(LDAPBindError) as caught:
        client.bind()
    assert caught.value is failure
    assert len(calls) == len(client._build_attempt_plan()) > 1
    assert client._credential_failure is None


def test_real_library_exception_class_keeps_its_previous_recognition(monkeypatch):
    from ldap3.core.exceptions import LDAPInvalidCredentialsResult

    client, _ = selected_client(monkeypatch)
    failure = LDAPInvalidCredentialsResult(result=49, message="data 52e")
    calls = rejected_provider(monkeypatch, client, failure)
    with pytest.raises(LDAPInvalidCredentialsResult):
        client.bind()
    assert len(calls) == 1
    assert client._credential_failure is failure
