"""Check native paging, binary values, safe fallback selection and actual cleanup."""

import struct
import uuid

import pytest
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPCommunicationError,
    LDAPInvalidFilterError,
)

from openhound_collector_common.clients import ad, windows_ldap
from openhound_collector_common.clients.operations import (
    ClientCleanupError,
    ReadControl,
)
from windows_ldap_fixtures import WindowsLdapApi
from types import SimpleNamespace


def row(name="first"):
    sid = bytes([1, 4]) + (5).to_bytes(6, "big") + struct.pack("<IIII", 21, 1, 2, 1234)
    return (
        f"CN={name},DC=example,DC=com",
        {
            "name": [name.encode()],
            "objectSid": [sid],
            "objectGUID": [uuid.UUID("01234567-89ab-cdef-0123-456789abcdef").bytes_le],
            "servicePrincipalName": [b"HOST/first", b"MSSQLSvc/first:1433"],
        },
    )


def client(monkeypatch, pages, port=389):
    api = WindowsLdapApi(pages)
    monkeypatch.setattr(windows_ldap, "_load_api", lambda: api)
    monkeypatch.setattr(
        windows_ldap.socket,
        "getaddrinfo",
        lambda *args: [(2, 1, 6, "", ("10.10.10.100", 0))],
    )
    return windows_ldap.WindowsLdapClient("selected-dc", port, ReadControl(2)), api


def search(native, size_limit=0):
    return native.search(
        "(objectClass=computer)",
        ["name", "objectSid", "objectGUID", "servicePrincipalName"],
        "DC=example,DC=com",
        "SUBTREE",
        size_limit,
        2,
    )


def test_all_pages_including_final_page_keep_binary_and_multivalue_attributes(
    monkeypatch,
):
    native, api = client(
        monkeypatch, [(0, [row(), row("second")]), (94, [row("third")])]
    )
    rows = [ad.AdClient._entry_to_dict(entry) for entry in search(native)]
    assert [entry["name"] for entry in rows] == ["first", "second", "third"]
    assert rows[0]["objectSid"] == "S-1-5-21-1-2-1234"
    assert rows[0]["objectGuid"] == "01234567-89ab-cdef-0123-456789abcdef"
    assert rows[0]["servicePrincipalName"] == ["HOST/first", "MSSQLSvc/first:1433"]
    assert api.requested_pages == [2, 2]
    assert api.options[0x08] == api.options[0x91] == api.options[0x3F] == 0
    assert api.options[0x95] == api.options[0x96] == 1
    assert api.cleaned.count("page") == 2
    assert api.cleaned[-2:] == ["search", "connection"]
    assert native._handle is None


def test_empty_continuation_is_not_misreported_as_end_of_results(monkeypatch):
    native, api = client(monkeypatch, [(0, []), (94, [row()])])
    assert len(list(search(native))) == 1
    assert len(api.requested_pages) == 2


def test_explicit_limit_is_global_across_pages(monkeypatch):
    native, api = client(
        monkeypatch, [(0, [row(), row("second")]), (94, [row("third")])]
    )
    assert len(list(search(native, size_limit=3))) == 3
    assert api.requested_pages == [2, 1]


def test_partial_page_error_preserves_complete_entries_and_reports_failure(monkeypatch):
    native, api = client(monkeypatch, [(85, [row()])])
    entries = search(native)
    assert next(entries).entry_dn.startswith("CN=first,")
    with pytest.raises(windows_ldap.WindowsLdapError, match="code 85"):
        next(entries)
    assert api.cleaned[-2:] == ["search", "connection"]


def test_abandoned_consumer_releases_page_search_and_connection(monkeypatch):
    native, api = client(monkeypatch, [(0, [row(), row("second")])])
    entries = search(native)
    next(entries)
    entries.close()
    assert api.cleaned[-3:] == ["page", "search", "connection"]


def test_native_credential_failure_releases_connection_without_starting_search(
    monkeypatch,
):
    native, api = client(monkeypatch, [])
    api.bind_code = 49
    with pytest.raises(windows_ldap.WindowsLdapError, match="code 49"):
        list(search(native))
    assert api.cleaned == ["connection"]
    assert api.requested_pages == []


def test_cleanup_error_is_fatal_after_other_native_resources_are_released(monkeypatch):
    native, api = client(monkeypatch, [(94, [row()])])
    api.cleanup_code = 82
    with pytest.raises(ClientCleanupError):
        list(search(native))
    assert api.cleaned[-2:] == ["search", "connection"]


def test_standard_tls_port_keeps_the_selected_port_and_does_not_disable_validation(
    monkeypatch,
):
    native, api = client(monkeypatch, [(94, [])], port=636)
    list(search(native))
    assert api.destination == ("10.10.10.100", 636)
    assert api.has_tls
    assert 0x95 not in api.options and 0x96 not in api.options
    assert 0x81 not in api.options  # No certificate-validation override.


def fallback_client(monkeypatch, error=None, auth=None):
    monkeypatch.setattr(ad.sys, "platform", "win32")
    selected = ad.AdClient(
        "example.com", "selected-dc", auth, native_fallback=ReadControl(2)
    )
    error = error or LDAPCommunicationError("controlled integrated transport failure")
    monkeypatch.setattr(selected, "bind", lambda: (_ for _ in ()).throw(error))
    return selected


def test_eligible_failure_uses_native_output_and_saves_truthful_completed_outcome(
    monkeypatch,
):
    native, api = client(monkeypatch, [(94, [row()])])
    selected = fallback_client(monkeypatch)
    monkeypatch.setattr(ad, "WindowsLdapClient", lambda *args: native)
    rows = list(selected.paged_search("(objectClass=computer)", ["name"]))
    assert rows[0]["name"] == "first"
    assert selected.selected_backend == "windows"
    assert selected.last_query_result.state == "completed"
    assert selected.last_query_result.operation == "Windows LDAP search"


@pytest.mark.parametrize(
    "auth",
    [
        ad.LdapAuth(username="explicit-user", password="password"),
        ad.LdapAuth(username="explicit-user", nt_hash="a" * 32),
        ad.LdapAuth(kerberos_ticket="selected-ticket"),
        ad.LdapAuth(kerberos_ccache="selected-cache"),
        ad.LdapAuth(kerberos_keytab="selected-keytab"),
        ad.LdapAuth(username="selected-user"),
        ad.LdapAuth(password="secret"),
        ad.LdapAuth(kerberos_realm="EXAMPLE.COM"),
    ],
)
def test_explicit_selections_never_switch_to_current_windows_identity(
    monkeypatch, auth
):
    selected = fallback_client(monkeypatch, auth=auth)
    assert not selected._can_use_native_fallback(LDAPCommunicationError("failure"))


@pytest.mark.parametrize(
    "error",
    [
        LDAPBindError("invalidCredentials data 52e"),
        LDAPBindError("invalidCredentials"),
        LDAPInvalidFilterError("bad filter"),
        ValueError("bad input"),
    ],
)
def test_rejections_and_nontransport_errors_never_trigger_fallback(monkeypatch, error):
    selected = fallback_client(monkeypatch, error=error)
    assert not selected._can_use_native_fallback(error)


def test_proxy_and_unsupported_platform_never_trigger_native_networking(monkeypatch):
    selected = fallback_client(monkeypatch)
    monkeypatch.setattr(ad, "active_proxy", lambda: object())
    assert not selected._can_use_native_fallback(OSError("failure"))
    monkeypatch.setattr(ad, "active_proxy", lambda: None)
    monkeypatch.setattr(ad.sys, "platform", "linux")
    assert not selected._can_use_native_fallback(OSError("failure"))


def test_additional_controls_are_rejected_instead_of_silently_dropped(monkeypatch):
    selected = fallback_client(monkeypatch)
    monkeypatch.setattr(
        ad,
        "WindowsLdapClient",
        lambda *args: pytest.fail("Unsupported controls reached native networking"),
    )
    with pytest.raises(Exception, match="discard search controls"):
        list(
            selected.paged_search(
                "(objectClass=computer)", ["name"], controls=["unsupported-control"]
            )
        )
    assert selected.last_query_result.state == "failed"


def test_query_with_partly_returned_rows_never_repeats_through_another_provider(
    monkeypatch,
):
    selected = fallback_client(monkeypatch)
    connection = SimpleNamespace(entries=[], result={})
    calls = []

    def find(**kwargs):
        calls.append(True)
        if len(calls) > 1:
            raise LDAPCommunicationError("second page connection failure")
        connection.entries = [windows_ldap.WindowsDirectoryEntry("CN=first", {})]
        connection.result = {
            "description": "success",
            "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b"continue"}}},
        }

    connection.search = find
    monkeypatch.setattr(selected, "bind", lambda: connection)
    monkeypatch.setattr(
        ad,
        "WindowsLdapClient",
        lambda *args: pytest.fail("Partly returned search changed providers"),
    )
    assert list(selected.paged_search("(objectClass=computer)", ["name"])) == [
        {"distinguishedName": "CN=first"}
    ]
    assert selected.last_query_result.state == "failed"
    assert selected.selected_backend == "ldap3"


def test_requested_missing_attributes_keep_ldap3_empty_value_shape(monkeypatch):
    native, api = client(monkeypatch, [(94, [("CN=first", {"name": [b"first"]})])])
    entry = next(search(native))
    converted = ad.AdClient._entry_to_dict(entry)
    assert converted["objectSid"] is None and converted["servicePrincipalName"] is None


def test_unsupported_ranged_attribute_is_visible_and_cleans_up(monkeypatch):
    native, api = client(
        monkeypatch, [(94, [("CN=group", {"member;range=0-1499": [b"first"]})])]
    )
    with pytest.raises(windows_ldap.WindowsLdapError, match="ranged attribute"):
        list(search(native))
    assert api.cleaned[-3:] == ["page", "search", "connection"]


def test_overlapping_searches_cannot_replace_the_original_native_handle(monkeypatch):
    native, api = client(monkeypatch, [(0, [row()])])
    first = search(native)
    next(first)
    try:
        with pytest.raises(RuntimeError, match="overlapping searches"):
            next(search(native))
        assert native._handle == 1
    finally:
        first.close()
    assert api.cleaned[-2:] == ["search", "connection"]


def test_unexpected_native_cleanup_exception_still_closes_connection_and_is_fatal(
    monkeypatch,
):
    native, api = client(monkeypatch, [(94, [])])

    def fail(*args):
        raise OSError("injected native cleanup failure")

    api.ldap_search_abandon_page = fail
    with pytest.raises(ClientCleanupError):
        list(search(native))
    assert api.cleaned[-1] == "connection"


def test_normal_successful_empty_search_does_not_use_native_fallback(monkeypatch):
    selected = fallback_client(monkeypatch)
    connection = SimpleNamespace(
        entries=[], result={"description": "success"}, search=lambda **kwargs: None
    )
    monkeypatch.setattr(selected, "bind", lambda: connection)
    monkeypatch.setattr(
        ad,
        "WindowsLdapClient",
        lambda *args: pytest.fail("A successful search switched to native LDAP"),
    )
    assert list(selected.paged_search("(objectClass=computer)", ["name"])) == []
    assert selected.selected_backend == "ldap3"
    assert selected.last_query_result.state == "completed"
    assert selected.last_query_result.row_count == 0


def test_go_generic_current_user_failure_allows_the_selected_native_fallback(
    monkeypatch,
):
    native, api = client(monkeypatch, [(94, [row()])])
    # Preserve the exact Go example. Definite bad-password/disabled-account
    # statuses and explicit identities have separate refusal tests above.
    selected = fallback_client(
        monkeypatch, error=LDAPBindError("LDAP Result Code 49 Invalid Credentials")
    )
    monkeypatch.setattr(ad, "WindowsLdapClient", lambda *args: native)
    assert (
        list(selected.paged_search("(objectClass=computer)", ["name"]))[0]["name"]
        == "first"
    )
    assert selected.selected_backend == "windows"
    assert api.cleaned[-2:] == ["search", "connection"]


def test_default_native_page_request_preserves_the_go_thousand_entry_limit(monkeypatch):
    native, api = client(monkeypatch, [(94, [])])
    selected = fallback_client(monkeypatch)
    monkeypatch.setattr(ad, "WindowsLdapClient", lambda *args: native)
    assert list(selected.paged_search("(objectClass=computer)", ["name"])) == []
    assert api.requested_pages == [1000]
    assert api.cleaned[-2:] == ["search", "connection"]


@pytest.mark.parametrize(
    "provider_message",
    [
        "all LDAP connection methods failed: LDAPS failed\n\nTroubleshooting suggestions for Kerberos authentication failures:\n  1. Verify your Kerberos ticket is valid\n\nNote: The domain controller requires LDAP signing.",
        "all LDAP connection methods failed: LDAP failed\n\nNote: The domain controller requires LDAP signing.",
    ],
)
def test_native_fallback_log_does_not_repeat_provider_troubleshooting_text(
    monkeypatch, caplog, provider_message
):
    native, api = client(monkeypatch, [(94, [row()])])
    selected = fallback_client(
        monkeypatch, error=LDAPCommunicationError(provider_message)
    )
    monkeypatch.setattr(ad, "WindowsLdapClient", lambda *args: native)
    caplog.set_level("DEBUG", logger=ad.__name__)
    assert (
        list(selected.paged_search("(objectClass=computer)", ["name"]))[0]["name"]
        == "first"
    )
    assert "Using current-user Windows LDAP after eligible ldap3 failure" in caplog.text
    assert "Troubleshooting suggestions" not in caplog.text
    assert "requires LDAP signing" not in caplog.text
    assert api.cleaned[-2:] == ["search", "connection"]
