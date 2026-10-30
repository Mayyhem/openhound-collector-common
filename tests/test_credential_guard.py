"""One rejected sign-in stops every later sign-in in the same run.

The lab showed a wrong password costing dozens of failed sign-ins in one run:
each directory search signed in again, and every computer tried the same
password. These checks cover the shared pieces of the fix: the run-wide
record, the directory client's handling of the real rejection message, the
one-time sign-in check, and the WMI and Kerberos reports to the record.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from ldap3 import AUTO_BIND_NONE
from ldap3.core.exceptions import LDAPBindError

from openhound_collector_common.clients import ad, wmi
from openhound_collector_common.clients.credential_guard import (
    CREDENTIALS_REJECTED_REASON,
    CredentialCheck,
    CredentialGuard,
    CredentialsRejectedError,
    is_rejected_sign_in,
)
from openhound_collector_common.clients.kerberos import (
    KerberosAcquisitionError,
    acquisition_failure,
)
from openhound_collector_common.clients.operations import ReadControl

# The exact text ldap3's one-step automatic bind raised in the lab run.
AUTOMATIC_BIND_REJECTION = "automatic bind not successful - invalidCredentials"
# The result the domain controller actually returned for the wrong password.
REJECTED_BIND_RESULT = {
    "result": 49,
    "description": "invalidCredentials",
    "dn": "",
    "message": "80090308: LdapErr: DSID-0C09050F, comment: AcceptSecurityContext error, data 52e, v4563\x00",
    "referrals": None,
    "type": "bindResponse",
}
EXAMPLE_PASSWORD = "illustrative-password-must-not-appear"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("An offline sign-in check attempted a network connection")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def directory_client(monkeypatch, guard=None, *, controlled=False, password=True):
    """A real client whose only replaced parts are discovery and the provider."""
    client = ad.AdClient(
        "example.test",
        dc="dc.example.test",
        auth=ad.LdapAuth(username="EXAMPLE\\reader", password=EXAMPLE_PASSWORD)
        if password
        else ad.LdapAuth(),
        read_control=ReadControl(2) if controlled else None,
        credential_guard=guard,
    )
    monkeypatch.setattr(
        client,
        "_prepare_attempts_and_host",
        lambda attempts: (attempts, "dc.example.test"),
    )
    return client


def failing_provider(monkeypatch, client, failure):
    calls = []

    def open_connection(*, host, attempt):
        calls.append(attempt.label)
        raise failure

    monkeypatch.setattr(client, "_open_connection", open_connection)
    return calls


# --- the run-wide record ----------------------------------------------------


def test_first_rejection_runs_stop_actions_once_and_blocks_later_sign_ins(caplog):
    guard = CredentialGuard()
    stops = []
    guard.add_stop_action(lambda: stops.append("queue stopped"))
    guard.check_before_sign_in("a first sign-in")  # Nothing rejected yet.
    guard.record_rejection("The domain controller dc.example.test")
    guard.record_rejection("WMI on host.example.test")  # Ignored: already stopping.
    assert stops == ["queue stopped"]
    assert guard.is_rejected
    assert guard.rejected_by == "The domain controller dc.example.test"
    with pytest.raises(CredentialsRejectedError, match="no further sign-ins"):
        guard.check_before_sign_in("an SMB sign-in on host.example.test")
    assert "stopping the whole run" in caplog.text


def test_stop_action_added_after_a_rejection_runs_immediately():
    guard = CredentialGuard()
    guard.record_rejection("The domain controller")
    stops = []
    guard.add_stop_action(lambda: stops.append(True))
    assert stops == [True]


def test_simultaneous_rejections_from_many_workers_stop_the_run_once():
    guard = CredentialGuard()
    stops = []
    guard.add_stop_action(lambda: stops.append(True))
    start_together = Barrier(8)

    def reject(index):
        start_together.wait()
        guard.record_rejection(f"worker {index}")

    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(reject, range(8)))
    assert stops == [True]


@pytest.mark.parametrize("code", [6, 18, 23, 24])
def test_kerberos_refusals_of_the_account_or_password_are_definite(code):
    assert is_rejected_sign_in(KerberosAcquisitionError("refused", kdc_error_code=code))


@pytest.mark.parametrize("code", [None, 37, 68])
def test_other_kerberos_failures_are_not_treated_as_a_wrong_password(code):
    # 37 is a clock difference and 68 a wrong realm: neither proves the password.
    assert not is_rejected_sign_in(
        KerberosAcquisitionError("failed", kdc_error_code=code)
    )


def test_windows_wrong_password_status_is_definite_but_access_denied_is_not():
    class Status(Exception):
        def __init__(self, code):
            super().__init__("illustrative")
            self.code = code

        def get_error_code(self):
            return self.code

    assert is_rejected_sign_in(Status(0xC000006D))  # STATUS_LOGON_FAILURE
    assert not is_rejected_sign_in(Status(0x80070005))  # access denied
    # A correct account without SQL access also gets "Login failed".
    assert not is_rejected_sign_in(
        RuntimeError("Login failed for user 'EXAMPLE\\reader'.")
    )
    assert is_rejected_sign_in(CredentialsRejectedError(CREDENTIALS_REJECTED_REASON))


# --- the directory client ---------------------------------------------------


@pytest.mark.parametrize("controlled", [False, True])
def test_real_automatic_bind_message_stops_after_one_failed_sign_in(
    monkeypatch, controlled
):
    guard = CredentialGuard()
    client = directory_client(monkeypatch, guard, controlled=controlled)
    calls = failing_provider(
        monkeypatch, client, LDAPBindError(AUTOMATIC_BIND_REJECTION)
    )
    assert len(client._build_attempt_plan()) > 1
    for _ in range(3):
        with pytest.raises(LDAPBindError):
            client.bind()
    assert len(calls) == 1
    assert guard.is_rejected


def test_current_windows_user_keeps_its_existing_profile_retries(monkeypatch):
    # No password was typed, so a reply without a reason cannot be a wrong
    # password. The Go reference lets this identity try its other choices.
    guard = CredentialGuard()
    client = directory_client(monkeypatch, guard, password=False)
    calls = failing_provider(
        monkeypatch, client, LDAPBindError(AUTOMATIC_BIND_REJECTION)
    )
    with pytest.raises(LDAPBindError):
        client.bind()
    assert len(calls) == len(client._build_attempt_plan())
    assert not guard.is_rejected


def test_rejection_in_one_client_stops_another_client_in_the_same_run(monkeypatch):
    guard = CredentialGuard()
    first = directory_client(monkeypatch, guard)
    second = directory_client(monkeypatch, guard)
    first_calls = failing_provider(
        monkeypatch, first, LDAPBindError("invalidCredentials: data 52e")
    )
    second_calls = failing_provider(
        monkeypatch, second, AssertionError("must not sign in")
    )
    with pytest.raises(LDAPBindError):
        first.bind()
    with pytest.raises(CredentialsRejectedError):
        second.bind()
    assert len(first_calls) == 1
    assert second_calls == []


def test_channel_binding_reply_still_tries_the_next_profile_with_a_guard(monkeypatch):
    guard = CredentialGuard()
    client = directory_client(monkeypatch, guard)
    calls = failing_provider(
        monkeypatch, client, LDAPBindError("Invalid Credentials: data 80090346")
    )
    with pytest.raises(LDAPBindError):
        client.bind()
    assert len(calls) == len(client._build_attempt_plan()) > 1
    assert not guard.is_rejected


@pytest.mark.parametrize("controlled", [False, True])
def test_every_password_bind_keeps_the_domain_controllers_reason(
    monkeypatch, controlled
):
    """Run the real connection-opening code against a stand-in for ldap3."""
    events = []

    class Server:
        def __init__(self, host, **settings):
            self.host = host

    class Connection:
        def __init__(self, server, **settings):
            events.append(("created", settings["auto_bind"]))
            self.result = REJECTED_BIND_RESULT
            self.bound = False
            self.socket = None

        def open(self, read_server_info=True):
            events.append("open")

        def start_tls(self, read_server_info=True):
            events.append("start_tls")
            return True

        def bind(self, read_server_info=True):
            events.append(("bind", read_server_info))
            return False

        def refresh_server_info(self):
            events.append("refresh")

        def unbind(self):
            events.append("unbind")

    monkeypatch.setattr(ad, "Server", Server)
    monkeypatch.setattr(ad, "Connection", Connection)
    guard = CredentialGuard()
    client = directory_client(monkeypatch, guard, controlled=controlled)
    with pytest.raises(LDAPBindError) as caught:
        client.bind()
    assert "data 52e" in str(caught.value)
    # One connection, opened step by step, rejected, and released.
    assert events == [("created", AUTO_BIND_NONE), "open", ("bind", False), "unbind"]
    assert guard.is_rejected
    assert client._conn is None and client._opening_conn is None


def test_sign_in_check_reports_accepted_rejected_unchecked_and_not_needed(monkeypatch):
    accepted = directory_client(monkeypatch)

    class Bound:
        bound = True

        def unbind(self):
            pass

    monkeypatch.setattr(accepted, "_open_connection", lambda *, host, attempt: Bound())
    assert accepted.confirm_credentials() is CredentialCheck.ACCEPTED

    guard = CredentialGuard()
    rejected = directory_client(monkeypatch, guard)
    calls = failing_provider(
        monkeypatch, rejected, LDAPBindError(AUTOMATIC_BIND_REJECTION)
    )
    assert rejected.confirm_credentials() is CredentialCheck.REJECTED
    assert len(calls) == 1 and guard.is_rejected

    unreachable = directory_client(monkeypatch)
    failing_provider(
        monkeypatch, unreachable, OSError("no route to the domain controller")
    )
    assert unreachable.confirm_credentials() is CredentialCheck.UNCHECKED

    windows_session = directory_client(monkeypatch, password=False)
    failing_provider(monkeypatch, windows_session, AssertionError("must not sign in"))
    assert windows_session.confirm_credentials() is CredentialCheck.NOT_NEEDED


# --- the WMI client ---------------------------------------------------------


class _Status(Exception):
    def __init__(self, code):
        super().__init__("illustrative provider failure")
        self.code = code

    def get_error_code(self):
        return self.code


def wmi_client(monkeypatch, guard, failure=None):
    calls = []

    class Provider:
        def connect(self):
            calls.append(True)
            if failure is not None:
                raise failure

        def close(self):
            pass

    client = wmi.WmiClient(
        "host.example.test",
        wmi.WmiAuth(username="reader", password=EXAMPLE_PASSWORD),
        credential_guard=guard,
    )
    monkeypatch.setattr(client, "_build_backend", lambda mode: Provider())
    return client, calls


def test_wmi_does_not_sign_in_after_another_client_was_rejected(monkeypatch):
    guard = CredentialGuard()
    guard.record_rejection("The domain controller")
    client, calls = wmi_client(monkeypatch, guard)
    assert client.query("SELECT Name FROM Win32_Service") == []
    assert calls == []


def test_wmi_wrong_password_stops_the_run(monkeypatch, caplog):
    guard = CredentialGuard()
    client, calls = wmi_client(monkeypatch, guard, _Status(0xC000006D))
    assert client.query("SELECT Name FROM Win32_Service") == []
    assert calls == [True]
    assert guard.rejected_by == "WMI on host.example.test"
    assert EXAMPLE_PASSWORD not in caplog.text


def test_wmi_access_denied_does_not_stop_the_run(monkeypatch):
    guard = CredentialGuard()
    client, _ = wmi_client(monkeypatch, guard, _Status(0x80070005))
    assert client.query("SELECT Name FROM Win32_Service") == []
    assert not guard.is_rejected


# --- Kerberos ---------------------------------------------------------------


def test_kerberos_failure_keeps_the_domain_controllers_numeric_reason():
    class KdcReply(Exception):
        def getErrorCode(self):
            return 24  # KDC_ERR_PREAUTH_FAILED: wrong password

    failure = acquisition_failure(KdcReply("raw reply must not escape"))
    assert failure.kdc_error_code == 24
    assert failure.is_rejected_identity
    assert "raw reply" not in str(failure)
    assert not acquisition_failure(OSError("unreachable")).is_rejected_identity
