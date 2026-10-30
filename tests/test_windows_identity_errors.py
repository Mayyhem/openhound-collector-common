"""Definite rejected accounts stop retries; object permissions do not."""

from types import SimpleNamespace

import pytest
from ldap3.core.exceptions import LDAPBindError

from openhound_collector_common.clients import ad
from openhound_collector_common.clients.identity_errors import (
    is_windows_credential_rejection,
)


@pytest.mark.parametrize(
    "code",
    [
        0xC000006D,
        0xC0000072,
        0x8007052E,
        0x8009030C,
        -2146893044,
        0x80070532,
        0x80070533,
        0x80070701,
        0x80070773,
        0x80070775,
    ],
)
def test_native_hresult_rejection_is_recognized(code):
    error = RuntimeError("safe test error")
    error.hresult = code
    assert is_windows_credential_rejection(error)


def test_outer_automation_hresult_does_not_hide_rejected_account():
    error = RuntimeError("outer automation error")
    error.hresult = 0x80020009
    error.excepinfo = (0, "source", "description", None, 0, 0x8007052E)
    assert is_windows_credential_rejection(error)


@pytest.mark.parametrize(
    "message",
    ["SSPI failed (-2146893044)", "SEC_E_LOGON_DENIED", "The logon attempt failed"],
)
def test_wrapped_sspi_error_does_not_enable_native_identity_retry(message, monkeypatch):
    monkeypatch.setattr(ad.sys, "platform", "win32")
    error = LDAPBindError(message)
    assert is_windows_credential_rejection(error)
    client = ad.AdClient("example.com", native_fallback=ad.ReadControl(2))
    assert not client._can_use_native_fallback(error)


def test_object_access_denial_is_not_misclassified_as_bad_credentials():
    error = RuntimeError("Access denied to this object")
    error.hresult = 0x80070005
    assert not is_windows_credential_rejection(error)


def test_rejected_integrated_identity_stops_the_bind_plan_and_later_reads(monkeypatch):
    client = ad.AdClient("example.com")
    attempt = SimpleNamespace(auth_mode="sspi_ntlm", label="test", port=389)
    monkeypatch.setattr(client, "_build_attempt_plan", lambda: [attempt, attempt])
    monkeypatch.setattr(
        client, "_prepare_attempts_and_host", lambda attempts: (attempts, "selected-dc")
    )
    monkeypatch.setattr(client, "_log_credential_summary", lambda attempts: None)
    calls = []

    def fail(**kwargs):
        calls.append(True)
        raise LDAPBindError("Windows SSPI failed (-2146893044)")

    monkeypatch.setattr(client, "_open_connection", fail)
    for _ in range(2):
        with pytest.raises(LDAPBindError):
            client.bind()
    assert calls == [True]
