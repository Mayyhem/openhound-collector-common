"""A conventional port is a candidate, never a named-instance identity."""

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from openhound_collector_common.discovery.sql_fallback import (
    SqlPortFallback,
    sql_instance_name,
)
from openhound_collector_common.clients import mssql
from openhound_collector_common.clients.operations import (
    ClientCleanupError,
    ReadStoppedError,
)


def test_fallback_is_anonymous_and_reserved_once_across_workers():
    fallback = SqlPortFallback()
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(fallback.claim, ["SQL.LAB", "sql.lab."] * 8))
    candidates = [result for result in results if result is not None]
    assert len(candidates) == 1
    assert candidates[0].port == 1433 and candidates[0].instance is None
    assert SqlPortFallback().claim("sql.lab") is not None


def test_known_1433_prevents_a_duplicate_but_other_ports_do_not():
    fallback = SqlPortFallback()
    fallback.remember("sql.lab", 51433)
    assert fallback.claim("sql.lab") is not None
    fallback.remember("another.lab", 1433)
    assert fallback.claim("ANOTHER.LAB") is None


def test_existing_computer_identity_covers_different_hostname_aliases():
    fallback = SqlPortFallback()
    assert fallback.claim("short-name", host_identity="S-1-5-21-1-2-3-1001") is not None
    assert fallback.claim("full-name.lab", host_identity="S-1-5-21-1-2-3-1001") is None


@pytest.mark.parametrize(
    "row, expected",
    [
        ({"ServerName": "SQL\\Reports", "InstanceName": "Reports"}, "Reports"),
        ({"servername": "SQL", "instancename": None}, "MSSQLSERVER"),
    ],
)
def test_identity_comes_from_the_connected_engine(row, expected):
    assert sql_instance_name(row) == expected


@pytest.mark.parametrize(
    "row",
    [
        {},
        {"InstanceName": None},
        {"ServerName": "SQL"},
        {"ServerName": "SQL\\OTHER", "InstanceName": "REPORTS"},
        {"ServerName": "SQL\\REPORTS", "InstanceName": None},
        {"ServerName": "SQL", "InstanceName": 7},
    ],
)
def test_missing_or_inconsistent_identity_cannot_become_default(row):
    with pytest.raises(ValueError, match="identity"):
        sql_instance_name(row)


@pytest.mark.parametrize("is_query_failure", [False, True])
@pytest.mark.parametrize("is_login_success", [False, True])
def test_epa_reads_identity_only_on_the_existing_normal_login(
    monkeypatch, is_query_failure, is_login_success
):
    reads = []
    clients = []

    class Client:
        epa_encryption_flag = mssql.ENCRYPT_OFF
        epa_is_strict = False

        def __init__(self, *args):
            clients.append(self)
            self.closed = False

        def connect(self, **kwargs):
            pass

        def login_epa(self, **kwargs):
            return is_login_success

        def get_error_messages(self):
            return "Login failed for user"

        def RunSQLQuery(self, database, sql):
            reads.append(sql)
            if is_query_failure:
                raise OSError("identity read failed")
            return [{"ServerName": "SQL\\REPORTS", "InstanceName": "REPORTS"}]

        def disconnect(self):
            self.closed = True

    monkeypatch.setattr(mssql, "_Tds", Client)
    result = mssql.detect_epa(
        "sql.lab:1433", mssql.Auth(username="reader"), identify_instance=True
    )
    assert result["extendedProtection"] == "Off"
    assert result["instanceName"] == (
        "REPORTS" if is_login_success and not is_query_failure else None
    )
    assert len(reads) == int(is_login_success) and len(clients) == 2
    assert all(client.closed for client in clients)


@pytest.mark.parametrize("failure", [ReadStoppedError, ClientCleanupError])
def test_identity_stop_or_fatal_failure_prevents_further_epa_logins(
    monkeypatch, failure
):
    logins = []
    closed = []

    def stopped_query(*args):
        raise failure("identity read stopped")

    client = SimpleNamespace(
        connect=lambda **kwargs: None,
        login_epa=lambda **kwargs: logins.append("normal") or True,
        RunSQLQuery=stopped_query,
        disconnect=lambda: closed.append(True),
        epa_encryption_flag=mssql.ENCRYPT_OFF,
        epa_is_strict=False,
    )
    monkeypatch.setattr(mssql, "_Tds", lambda *args: client)
    with pytest.raises(failure):
        mssql.detect_epa(
            "sql.lab:1433", mssql.Auth(username="reader"), identify_instance=True
        )
    assert logins == ["normal"] and closed == [True]
