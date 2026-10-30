"""A failed LDAP lookup must remain distinguishable from a successful empty read."""

from types import SimpleNamespace

import pytest
from ldap3.core.exceptions import LDAPBindError, LDAPException

from openhound_collector_common.clients.ad import AdClient


class Reader(AdClient):
    @staticmethod
    def _entry_to_dict(entry):
        return entry


def reader(monkeypatch, *, entries=(), result=None, failure=None):
    outcomes = []
    client = Reader("example.com", on_query=outcomes.append)

    def search(**kwargs):
        if failure:
            raise failure

    connection = SimpleNamespace(
        search=search,
        entries=list(entries),
        result=result or {"description": "success"},
    )
    monkeypatch.setattr(client, "bind", lambda: connection)
    return client, outcomes


def test_successful_empty_read_records_zero(monkeypatch):
    client, outcomes = reader(monkeypatch)
    assert list(client.paged_search("(objectClass=computer)", ["name"])) == []
    assert outcomes[0].state == "completed" and outcomes[0].row_count == 0


def test_missing_protocol_result_is_a_failed_read(monkeypatch):
    client, outcomes = reader(monkeypatch)
    monkeypatch.setattr(
        client,
        "bind",
        lambda: SimpleNamespace(search=lambda **kwargs: None, result={}, entries=[]),
    )
    assert list(client.paged_search("(name=*)", ["name"])) == []
    assert outcomes[0].state == "failed" and outcomes[0].row_count is None


@pytest.mark.parametrize(
    "result,failure",
    [
        ({"description": "insufficientAccessRights"}, None),
        ({"description": "success"}, LDAPException("unfiltered provider detail")),
    ],
)
def test_failed_read_has_unknown_count_and_a_safe_reason(monkeypatch, result, failure):
    client, outcomes = reader(monkeypatch, result=result, failure=failure)
    assert list(client.paged_search("(private-filter=value)", ["name"])) == []
    assert outcomes[0].state == "failed" and outcomes[0].row_count is None
    assert "private-filter" not in str(outcomes[0].as_row())
    assert "unfiltered provider detail" not in str(outcomes[0].as_row())


def test_bind_failure_is_still_raised_and_is_also_recorded(monkeypatch):
    outcomes = []
    client = Reader("example.com", on_query=outcomes.append)

    def fail():
        raise LDAPBindError("data 52e")

    monkeypatch.setattr(client, "bind", fail)
    with pytest.raises(LDAPBindError):
        list(client.paged_search("(name=account)", ["name"]))
    assert outcomes[0].state == "failed" and outcomes[0].row_count is None


def test_server_truncation_retains_complete_rows_but_records_incompleteness(
    monkeypatch,
):
    client, outcomes = reader(
        monkeypatch,
        entries=[{"name": "one"}],
        result={"description": "sizeLimitExceeded"},
    )
    assert list(client.paged_search("(name=*)", ["name"])) == [{"name": "one"}]
    assert outcomes[0].state == "failed"


def test_intentional_first_match_finalizes_its_completed_outcome(monkeypatch):
    client, outcomes = reader(
        monkeypatch,
        entries=[{"name": "one"}],
        result={"description": "sizeLimitExceeded"},
    )
    assert client._first_entry("(name=*)", ["name"]) == {"name": "one"}
    assert len(outcomes) == 1 and outcomes[0].state == "completed"


def test_rejected_identity_is_not_submitted_again(monkeypatch):
    client = AdClient("example.com")
    attempts = []
    monkeypatch.setattr(
        client, "_build_attempt_plan", lambda: [SimpleNamespace(label="controlled")]
    )
    monkeypatch.setattr(
        client,
        "_prepare_attempts_and_host",
        lambda attempts: (attempts, "dc.example.com"),
    )
    monkeypatch.setattr(client, "_log_credential_summary", lambda attempts: None)

    def fail(**kwargs):
        attempts.append(True)
        raise LDAPBindError("invalidCredentials data 52e")

    monkeypatch.setattr(client, "_open_connection", fail)
    for _ in range(2):
        with pytest.raises(LDAPBindError):
            client.bind()
    assert attempts == [True]
