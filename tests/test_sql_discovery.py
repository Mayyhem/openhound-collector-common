"""SQL discovery must retain unknown ports and reject misleading replies."""

import struct
from contextlib import contextmanager
from threading import Event
from types import SimpleNamespace

import pytest

from openhound_collector_common.clients.mssql import parse_target
from openhound_collector_common.discovery import sql_browser
from openhound_collector_common.discovery.sql_server import (
    parse_sql_address,
    parse_sql_spn,
)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("sql.lab", ("sql.lab", 1433, None)),
        ("sql.lab:51433", ("sql.lab", 51433, None)),
        ("sql.lab,51433", ("sql.lab", 51433, None)),
        (r"sql.lab\REPORTS", ("sql.lab", None, "REPORTS")),
        (r"sql.lab\REPORTS:51433", ("sql.lab", 51433, "REPORTS")),
        (r"sql.lab\REPORTS,51433", ("sql.lab", 51433, "REPORTS")),
        ("MSSQLSvc/sql.lab:REPORTS", ("sql.lab", None, "REPORTS")),
        ("mssqlsvc/sql.lab:51433", ("sql.lab", 51433, None)),
        ("MSSQLSvc/sql.lab", ("sql.lab", None, None)),
    ],
)
def test_sql_addresses_keep_unknown_ports_unknown(text, expected):
    address = parse_sql_address(text)
    assert (address.host, address.port, address.instance) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "sql.lab:",
        "sql.lab,wrong",
        "sql.lab:0",
        "sql.lab:65536",
        r"sql.lab\REPORTS:wrong",
        "sql.lab\\",
        "bad host:1433",
    ],
)
def test_invalid_addresses_cannot_fall_back_to_default_port(text):
    with pytest.raises(ValueError):
        parse_sql_address(text)


def test_other_service_registrations_are_not_sql_addresses():
    assert parse_sql_spn("HTTP/sql.lab") is None


def test_connection_string_backslash_is_not_a_sql_spn_separator():
    with pytest.raises(ValueError, match="portOrInstance"):
        parse_sql_spn(r"MSSQLSvc/sql.lab\REPORTS")


@pytest.mark.parametrize(
    "text", [r"sql.lab\REPORTS", "MSSQLSvc/sql.lab:REPORTS", "MSSQLSvc/sql.lab"]
)
def test_connection_client_refuses_unresolved_discovery(text):
    with pytest.raises(ValueError, match="Resolve the SQL instance"):
        parse_target(text)


def packet(payload):
    return b"\x05" + struct.pack("<H", len(payload)) + payload


@pytest.mark.parametrize(
    "payload",
    [
        b"InstanceName;OTHER;tcp;51433;;",
        b"InstanceName;REPORTS;tcp;0;;",
        b"InstanceName;REPORTS;tcp;65536;;",
        b"InstanceName;REPORTS;tcp;bad;;",
        b"InstanceName;REPORTS;tcp;51433;tcp;1433;;",
        b"InstanceName;REPORTS;tcp;51433;",
    ],
)
def test_browser_rejects_wrong_instance_invalid_port_and_duplicate_keys(payload):
    with pytest.raises(ValueError):
        sql_browser.parse_browser_reply(packet(payload), "REPORTS")


def test_browser_does_not_decode_unrelated_localized_values_as_ascii():
    reply = packet(b"ServerName;SERV\xc9R;InstanceName;reports;tcp;51433;;")
    assert sql_browser.parse_browser_reply(reply, "REPORTS") == 51433


def test_browser_uses_explicit_common_code_page_for_non_ascii_instance():
    reply = packet("InstanceName;RÉPORTS;tcp;51433;;".encode("cp1252"))
    assert sql_browser.parse_browser_reply(reply, "réports", encoding="cp1252") == 51433
    with pytest.raises(ValueError, match="code page"):
        sql_browser.parse_browser_reply(reply, "RÉPORTS")


@pytest.mark.parametrize("name", ["", "A" * 33, "A\x00B"])
def test_browser_enforces_protocol_instance_name_limit_before_network(name):
    with pytest.raises(ValueError, match="1..32"):
        sql_browser.SqlBrowserResolver().resolve("sql.lab", name, timeout=1)


class FakeSocket:
    """An inert datagram socket; it never opens a real connection."""

    def __init__(self, reply):
        self.reply = reply
        self.requests = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        self.closed = True

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.address = address

    def send(self, request):
        self.requests.append(request)
        return len(request)

    def recv(self, size):
        assert size >= len(self.reply)
        return self.reply


def test_browser_queries_one_instance_and_caches_only_success(monkeypatch):
    connection = FakeSocket(packet(b"InstanceName;REPORTS;tcp;51433;;"))
    monkeypatch.setattr(sql_browser.socket, "socket", lambda *args: connection)
    monkeypatch.setattr(
        sql_browser,
        "resolve_socket_addresses",
        lambda *args: [(None, None, None, None, ("10.10.11.51", 1434))],
    )
    resolver = sql_browser.SqlBrowserResolver()
    assert resolver.resolve("sql.lab", "REPORTS", timeout=2) == 51433
    assert resolver.resolve("SQL.LAB", "reports", timeout=2) == 51433
    assert connection.requests == [b"\x04REPORTS\x00"]
    assert connection.address == ("10.10.11.51", 1434)
    assert connection.closed


def test_proxy_mode_does_not_open_udp(monkeypatch):
    def forbidden(*arguments):
        raise AssertionError("Proxy resolution must not open a UDP socket")

    monkeypatch.setattr(sql_browser.socket, "socket", forbidden)
    with pytest.raises(ValueError, match="UDP"):
        sql_browser.SqlBrowserResolver().resolve(
            "sql.lab", "REPORTS", timeout=1, proxied=True
        )


def test_browser_accepts_exactly_32_bytes():
    name = "A" * 32
    assert (
        sql_browser.parse_browser_reply(
            packet(f"InstanceName;{name};tcp;51433;;".encode("ascii")), name
        )
        == 51433
    )


def test_browser_socket_inherits_parent_timeout_and_stop_event(monkeypatch):
    connection = FakeSocket(packet(b"InstanceName;REPORTS;tcp;51433;;"))
    stop_event = Event()
    parent = SimpleNamespace(
        check=lambda: None, remaining=lambda: 0.25, deadline=None, stop_event=stop_event
    )
    controls = []

    @contextmanager
    def controlled(control, label, owned_socket):
        controls.append((control, label, owned_socket))
        yield

    monkeypatch.setattr(sql_browser, "current_read_operation", lambda: parent)
    monkeypatch.setattr(sql_browser, "socket_read", controlled)
    monkeypatch.setattr(sql_browser.socket, "socket", lambda *args: connection)
    monkeypatch.setattr(
        sql_browser,
        "resolve_socket_addresses",
        lambda *args: [(None, None, None, None, ("10.10.11.51", 1434))],
    )
    assert (
        sql_browser.SqlBrowserResolver().resolve("sql.lab", "REPORTS", timeout=10)
        == 51433
    )
    control, label, owned_socket = controls[0]
    assert control.stop_event is stop_event
    assert connection.timeout == 0.25
    assert owned_socket is connection
    assert label == "SQL Browser read"


def test_stopped_parent_prevents_browser_socket_creation(monkeypatch):
    from openhound_collector_common.clients.operations import ReadStoppedError

    def stopped():
        raise ReadStoppedError("Read was stopped")

    monkeypatch.setattr(
        sql_browser, "current_read_operation", lambda: SimpleNamespace(check=stopped)
    )
    with pytest.raises(ReadStoppedError):
        sql_browser.SqlBrowserResolver().resolve("sql.lab", "REPORTS", timeout=1)


def test_bad_browser_reply_is_not_cached_as_a_port(monkeypatch):
    connection = FakeSocket(packet(b"InstanceName;OTHER;tcp;1433;;"))
    monkeypatch.setattr(sql_browser.socket, "socket", lambda *args: connection)
    monkeypatch.setattr(
        sql_browser,
        "resolve_socket_addresses",
        lambda *args: [(None, None, None, None, ("10.10.11.51", 1434))],
    )
    resolver = sql_browser.SqlBrowserResolver()
    with pytest.raises(ValueError):
        resolver.resolve("sql.lab", "REPORTS", timeout=1)
    connection.reply = packet(b"InstanceName;REPORTS;tcp;51433;;")
    assert resolver.resolve("sql.lab", "REPORTS", timeout=1) == 51433
    assert len(connection.requests) == 2
