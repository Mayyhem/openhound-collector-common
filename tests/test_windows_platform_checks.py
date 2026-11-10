"""Keep Windows-only calls explicit without using real consoles or connections."""

import ctypes
import io
import socket
import sys
from threading import Lock
from types import SimpleNamespace

import pytest

from openhound_collector_common.clients import operations, windows_ldap
from openhound_collector_common.logging import console


class Terminal(io.StringIO):
    """Supply a terminal-shaped stream without borrowing the test runner's console."""

    def isatty(self):
        return True

    def fileno(self):
        return 17


def test_non_windows_terminal_needs_no_windows_console_api(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda *args, **kwargs: pytest.fail("Windows API reached"),
        raising=False,
    )
    assert console.console_supports_color(Terminal()) is True


def test_windows_terminal_still_enables_console_processing(monkeypatch):
    calls = []

    def get_mode(handle, mode):
        calls.append(("get", handle))
        mode._obj.value = 0
        return True

    def set_mode(handle, mode):
        calls.append(("set", handle, mode))
        return True

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setitem(
        sys.modules, "msvcrt", SimpleNamespace(get_osfhandle=lambda fd: 123)
    )
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda *args, **kwargs: SimpleNamespace(
            GetConsoleMode=get_mode, SetConsoleMode=set_mode
        ),
        raising=False,
    )
    assert console.console_supports_color(Terminal()) is True
    assert calls == [("get", 123), ("set", 123, 4)]


def test_non_windows_com_cancellation_fails_before_loading_a_library(
    monkeypatch, caplog
):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda *args, **kwargs: pytest.fail("Windows API reached"),
        raising=False,
    )
    with pytest.raises(RuntimeError, match="Windows COM cancellation requires Windows"):
        operations.cancel_windows_call(42)
    assert "Windows COM cancellation is unavailable" in caplog.text


def test_windows_com_cancellation_still_uses_the_requested_thread(monkeypatch):
    calls = []

    def cancel(thread_id, timeout):
        calls.append((thread_id, timeout))
        return 0

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name: SimpleNamespace(CoCancelCall=cancel),
        raising=False,
    )
    operations.cancel_windows_call(42)
    assert calls == [(42, 0)]


def native_client_with_socket():
    """Expose only the fields read by cancellation, with an inert socket number."""

    def get_option(handle, option, descriptor):
        descriptor._obj.value = 123
        return 0

    native = windows_ldap.WindowsLdapClient.__new__(windows_ldap.WindowsLdapClient)
    native._guard = Lock()
    native._handle = ctypes.c_void_p(1)
    native._api = SimpleNamespace(ldap_get_optionW=get_option)
    return native


def test_non_windows_native_ldap_cancellation_fails_before_loading_a_library(
    monkeypatch, caplog
):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda *args, **kwargs: pytest.fail("Windows API reached"),
        raising=False,
    )
    with pytest.raises(
        RuntimeError, match="Native LDAP socket cancellation requires Windows"
    ):
        native_client_with_socket()._interrupt()
    assert "Native Windows LDAP socket cancellation is unavailable" in caplog.text


def test_windows_native_ldap_cancellation_still_stops_its_socket(monkeypatch):
    calls = []

    def shutdown(descriptor, how):
        calls.append((descriptor, how))
        return 0

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name: SimpleNamespace(shutdown=shutdown),
        raising=False,
    )
    native_client_with_socket()._interrupt()
    assert calls == [(123, socket.SHUT_RDWR)]
