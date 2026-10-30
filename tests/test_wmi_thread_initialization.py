"""Exercise native WMI ownership without requiring domain access or Windows."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from threading import get_ident
from types import ModuleType, SimpleNamespace

import pytest

from openhound_collector_common.clients.wmi import _PyWin32Backend


class ComError(Exception):
    def __init__(self, hresult):
        self.hresult = hresult


@pytest.fixture
def windows_calls(monkeypatch):
    calls = []
    behavior = SimpleNamespace(init_error=None, dispatch_error=None)
    pythoncom = ModuleType("pythoncom")
    pythoncom.error = ComError
    pythoncom.COINIT_MULTITHREADED = 0

    def initialize(model):
        calls.append(("initialize", get_ident()))
        if behavior.init_error is not None:
            raise ComError(behavior.init_error)

    def dispatch(name):
        calls.append(("dispatch", get_ident()))
        if behavior.dispatch_error:
            raise RuntimeError("Deliberate WMI object creation failure")
        return SimpleNamespace(
            ConnectServer=lambda *args: SimpleNamespace(ExecQuery=lambda *args: [])
        )

    pythoncom.CoInitializeEx = initialize
    pythoncom.CoUninitialize = lambda: calls.append(("release", get_ident()))
    pythoncom.CoEnableCallCancellation = lambda: calls.append(
        ("enable-cancellation", get_ident())
    )
    pythoncom.CoDisableCallCancellation = lambda: calls.append(
        ("disable-cancellation", get_ident())
    )
    client = ModuleType("win32com.client")
    client.Dispatch = dispatch
    win32com = ModuleType("win32com")
    win32com.client = client
    for name, module in (
        ("pythoncom", pythoncom),
        ("win32com", win32com),
        ("win32com.client", client),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return calls, behavior


def test_worker_initializes_before_dispatch_and_balances_cleanup(windows_calls):
    calls, _behavior = windows_calls
    main_thread = get_ident()

    def collect():
        backend = _PyWin32Backend("illustrative-target")
        backend.connect()
        backend.connect()  # Reusing this connection must not initialize twice.
        assert backend.execquery("root\\cimv2", "illustrative-query") == []
        backend.close()
        backend.close()

    with ThreadPoolExecutor(max_workers=1) as workers:
        workers.submit(collect).result(timeout=3)
    assert [name for name, _thread in calls] == ["initialize", "dispatch", "release"]
    assert len({thread for _name, thread in calls}) == 1
    assert calls[0][1] != main_thread


def test_dispatch_failure_releases_initialization_and_allows_retry(windows_calls):
    calls, behavior = windows_calls
    behavior.dispatch_error = True
    backend = _PyWin32Backend("illustrative-target")
    with pytest.raises(RuntimeError, match="creation failure"):
        backend.connect()
    behavior.dispatch_error = False
    backend.connect()
    backend.close()
    assert [name for name, _thread in calls] == [
        "initialize",
        "dispatch",
        "release",
    ] * 2


def test_preexisting_windows_model_is_used_without_releasing_callers_state(
    windows_calls,
):
    calls, behavior = windows_calls
    behavior.init_error = -2147417850  # RPC_E_CHANGED_MODE
    backend = _PyWin32Backend("illustrative-target")
    backend.connect()
    backend.close()
    assert [name for name, _thread in calls] == ["initialize", "dispatch"]


def test_other_initialization_failure_never_creates_wmi_objects(windows_calls):
    calls, behavior = windows_calls
    behavior.init_error = -2147024891
    with pytest.raises(ComError):
        _PyWin32Backend("illustrative-target").connect()
    assert [name for name, _thread in calls] == ["initialize"]


def test_wrong_thread_cannot_use_or_release_another_workers_objects(windows_calls):
    calls, _behavior = windows_calls
    backend = _PyWin32Backend("illustrative-target")
    backend.connect()

    def wrong_thread():
        for operation in (
            backend.close,
            lambda: backend.execquery("root\\cimv2", "query"),
        ):
            with pytest.raises(RuntimeError, match="connecting thread"):
                operation()

    with ThreadPoolExecutor(max_workers=1) as workers:
        workers.submit(wrong_thread).result(timeout=3)
    assert [name for name, _thread in calls] == ["initialize", "dispatch"]
    backend.close()
    assert calls[-1] == ("release", get_ident())


def test_monitored_read_can_enable_cancellation_after_explicit_preconnect(
    windows_calls,
):
    calls, _behavior = windows_calls
    backend = _PyWin32Backend("illustrative-target")
    backend.connect()
    backend.operation = SimpleNamespace(check=lambda: None)
    backend.connect()
    backend.close()
    assert [name for name, _thread in calls] == [
        "initialize",
        "dispatch",
        "enable-cancellation",
        "disable-cancellation",
        "release",
    ]
