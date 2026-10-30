"""Optional current-user Windows LDAP reads without another process.

This adapter calls the documented Unicode Windows LDAP API. It owns every native
allocation until copying the raw attribute bytes into Python. The existing AD
client then applies its usual SID/GUID and attribute conversion rules.
"""

from __future__ import annotations

import ctypes
import math
import socket
import sys
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock
from typing import Literal

from ldap3.core.exceptions import LDAPException

from ..logging import get_logger
from ..proxy import active_proxy
from .operations import ClientCleanupError, ReadControl, ReadOperation

logger = get_logger(__name__)
_SUCCESS = 0
_SIZE_LIMIT = 4
_NO_MORE_RESULTS = 94
_MAX_ENTRY_BYTES = 16 * 1024 * 1024
_ULONG = ctypes.c_uint32
_HANDLE = ctypes.c_void_p
_TEXT = ctypes.c_wchar_p


class _Timeval(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_int32), ("microseconds", ctypes.c_int32)]


class _Berval(ctypes.Structure):
    _fields_ = [("length", _ULONG), ("data", _HANDLE)]


class WindowsLdapError(LDAPException):
    """A safe native LDAP error code, without Windows authentication packets."""

    def __init__(self, operation: str, code: int) -> None:
        self.code = code
        super().__init__(f"Windows LDAP {operation} failed (code {code})")


@dataclass(frozen=True)
class _Attribute:
    raw_values: tuple[bytes, ...]


@dataclass(frozen=True)
class WindowsDirectoryEntry:
    """Raw entry fields consumed by the AD client's existing conversion method."""

    entry_dn: str
    attributes: dict[str, _Attribute]

    @property
    def entry_attributes(self) -> list[str]:
        return list(self.attributes)

    def __getitem__(self, name: str) -> _Attribute:
        return self.attributes[name]


def _load_api() -> ctypes.CDLL:
    """Declare the exact Windows SDK signatures at the native memory boundary."""
    if sys.platform != "win32":
        logger.error("Native Windows LDAP is unavailable on this platform")
        raise RuntimeError("Native LDAP fallback requires Windows")
    # LDAPAPI is __cdecl in Microsoft's Winldap.h. Use CDLL and fixed-width
    # Windows integers, including when an offline test runs on another platform.
    # CDLL functions have dynamic Python types; their exact native arguments and
    # pointer results are declared here before any call or memory access.
    api = ctypes.CDLL("Wldap32.dll")
    signatures = {
        "ldap_initW": ([_TEXT, _ULONG], _HANDLE),
        "ldap_sslinitW": ([_TEXT, _ULONG, _ULONG], _HANDLE),
        "ldap_set_optionW": ([_HANDLE, ctypes.c_int, _HANDLE], _ULONG),
        "ldap_get_optionW": ([_HANDLE, ctypes.c_int, _HANDLE], _ULONG),
        "ldap_connect": ([_HANDLE, ctypes.POINTER(_Timeval)], _ULONG),
        "ldap_bind_sW": ([_HANDLE, _TEXT, _HANDLE, _ULONG], _ULONG),
        "ldap_unbind": ([_HANDLE], _ULONG),
        "ldap_search_init_pageW": (
            [
                _HANDLE,
                _TEXT,
                _ULONG,
                _TEXT,
                ctypes.POINTER(_TEXT),
                _ULONG,
                _HANDLE,
                _HANDLE,
                _ULONG,
                _ULONG,
                _HANDLE,
            ],
            _HANDLE,
        ),
        "ldap_get_next_page_s": (
            [
                _HANDLE,
                _HANDLE,
                ctypes.POINTER(_Timeval),
                _ULONG,
                ctypes.POINTER(_ULONG),
                ctypes.POINTER(_HANDLE),
            ],
            _ULONG,
        ),
        "ldap_search_abandon_page": ([_HANDLE, _HANDLE], _ULONG),
        "ldap_first_entry": ([_HANDLE, _HANDLE], _HANDLE),
        "ldap_next_entry": ([_HANDLE, _HANDLE], _HANDLE),
        "ldap_get_dnW": ([_HANDLE, _HANDLE], _HANDLE),
        "ldap_first_attributeW": ([_HANDLE, _HANDLE, ctypes.POINTER(_HANDLE)], _HANDLE),
        "ldap_next_attributeW": ([_HANDLE, _HANDLE, _HANDLE], _HANDLE),
        "ldap_get_values_lenW": (
            [_HANDLE, _HANDLE, _TEXT],
            ctypes.POINTER(ctypes.POINTER(_Berval)),
        ),
        "ldap_value_free_len": ([ctypes.POINTER(ctypes.POINTER(_Berval))], _ULONG),
        "ldap_memfreeW": ([_HANDLE], None),
        "ldap_msgfree": ([_HANDLE], _ULONG),
        "ber_free": ([_HANDLE, ctypes.c_int], None),
        "LdapGetLastError": ([], _ULONG),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(api, name)
        function.argtypes = arguments
        function.restype = result
    return api


class WindowsLdapClient:
    """One explicitly addressed, signed/sealed current-user search at a time."""

    def __init__(self, host: str, port: int, control: ReadControl) -> None:
        self.host = host
        self.port = port
        self.control = control
        self._api: ctypes.CDLL | None = None
        self._handle: int | None = None
        self._search: int | None = None
        self._guard = Lock()
        self._search_guard = Lock()

    @contextmanager
    def _own_search(self) -> Iterator[None]:
        """Do not let overlapping generators replace this client's native handle."""
        if not self._search_guard.acquire(blocking=False):
            logger.error("A Windows LDAP client already has an active search")
            raise RuntimeError(
                "Use separate Windows LDAP clients for overlapping searches"
            )
        try:
            yield
        finally:
            self._search_guard.release()

    def _require_success(self, label: str, code: int) -> None:
        if code != _SUCCESS:
            logger.warning(
                "Windows LDAP %s failed on %s:%d (code %d)",
                label,
                self.host,
                self.port,
                code,
            )
            raise WindowsLdapError(label, code)
        # Successful low-level calls need no separate log line.

    def _seconds(self, operation: ReadOperation) -> int:
        operation.check()
        # Windows bind timeouts are per round trip and use whole seconds. The
        # monitor separately observes the elapsed read budget; neither promises
        # that a native call or cleanup returns exactly at that instant.
        return max(1, math.ceil(operation.deadline.remaining()))

    def _open(self, operation: ReadOperation) -> None:
        self._api = api = _load_api()
        operation.check()
        # Resolve before native networking so the run's selected Python resolver
        # chooses the actual destination. No serverless ADSI/DC discovery occurs.
        address = str(
            socket.getaddrinfo(
                self.host, self.port, socket.AF_INET, socket.SOCK_STREAM
            )[0][4][0]
        )
        use_tls = self.port in (636, 3269)
        with self._guard:
            self._handle = (
                api.ldap_sslinitW(address, self.port, 1)
                if use_tls
                else api.ldap_initW(address, self.port)
            )
        if not self._handle:
            raise WindowsLdapError("initialization", int(api.LdapGetLastError()))
        options = {
            0x11: 3,  # LDAP version 3.
            0x04: self._seconds(operation),  # Authentication round-trip timeout.
            0x42: self._seconds(operation),  # Limit a stalled send.
            0x08: 0,  # Never follow a referral to another server.
            0x91: 0,  # Never reconnect and resubmit credentials automatically.
            0x3F: 0,  # Never display a Windows credential prompt.
        }
        if not use_tls:
            options.update({0x95: 1, 0x96: 1})  # Require signed and sealed SSPI LDAP.
        # Native TLS uses Windows certificate validation; sign/seal options
        # cannot be combined with TLS. No certificate check is disabled.
        for option, selected in options.items():
            value = _ULONG(selected)
            self._require_success(
                "option",
                int(api.ldap_set_optionW(self._handle, option, ctypes.byref(value))),
            )
        timeout = _Timeval(self._seconds(operation), 0)
        self._require_success(
            "connection", int(api.ldap_connect(self._handle, ctypes.byref(timeout)))
        )
        operation.check()
        # Null credentials with LDAP_AUTH_NEGOTIATE select this Windows account.
        self._require_success(
            "authentication", int(api.ldap_bind_sW(self._handle, None, None, 0x486))
        )
        operation.check()
        logger.info(
            "Windows LDAP connected to selected DC %s:%d as the current user",
            self.host,
            self.port,
        )

    def _interrupt(self) -> None:
        """Interrupt only the socket still belonging to this native session."""
        with self._guard:
            if self._handle is None or self._api is None:
                return  # There is no exposed socket during early initialization.
            descriptor = ctypes.c_size_t(-1)
            result = self._api.ldap_get_optionW(
                self._handle, 0x01, ctypes.byref(descriptor)
            )
            if result == 0 and descriptor.value != ctypes.c_size_t(-1).value:
                shutdown = ctypes.WinDLL("Ws2_32.dll").shutdown
                shutdown.argtypes = (ctypes.c_size_t, ctypes.c_int)
                shutdown.restype = ctypes.c_int
                if shutdown(descriptor.value, socket.SHUT_RDWR) != 0:
                    logger.debug(
                        "Windows LDAP socket was already unavailable during cancellation"
                    )
            else:
                logger.debug("Windows LDAP has not exposed a cancellable socket yet")

    def _close(self) -> None:
        """A native cleanup error must escape a best-effort read as fatal."""
        try:
            self._close_owned()
        except ClientCleanupError:
            raise
        except Exception as error:
            logger.error("Windows LDAP native cleanup raised %s", type(error).__name__)
            raise ClientCleanupError("Windows LDAP cleanup failed") from error

    def _close_owned(self) -> None:
        """Free the search block and connection on their owner, even after failure."""
        failures: list[int] = []
        with self._guard:
            if self._api is None or self._handle is None:
                return  # Initialization did not allocate a native session.
            try:
                if self._search is not None:
                    result = int(
                        self._api.ldap_search_abandon_page(self._handle, self._search)
                    )
                    self._search = None
                    if result != _SUCCESS:
                        failures.append(result)
                        logger.warning(
                            "Windows LDAP search cleanup returned code %d", result
                        )
            finally:
                result = int(self._api.ldap_unbind(self._handle))
                self._handle = None
                if result != _SUCCESS:
                    failures.append(result)
                    logger.error(
                        "Windows LDAP connection cleanup returned code %d", result
                    )
        if failures:
            raise ClientCleanupError("Windows LDAP cleanup failed")

    def _entry(
        self, entry: int, operation: ReadOperation, requested: list[str]
    ) -> WindowsDirectoryEntry:
        """Copy all requested raw values before freeing their native allocations."""
        api = self._api
        assert api is not None and self._handle is not None
        dn_pointer = api.ldap_get_dnW(self._handle, entry)
        if not dn_pointer:
            raise WindowsLdapError("entry name", int(api.LdapGetLastError()))
        try:
            dn = ctypes.wstring_at(dn_pointer)
        finally:
            api.ldap_memfreeW(dn_pointer)
        attributes: dict[str, _Attribute] = {}
        iterator = _HANDLE()
        attribute_pointer = api.ldap_first_attributeW(
            self._handle, entry, ctypes.byref(iterator)
        )
        total_bytes = 0
        try:
            while attribute_pointer:
                try:
                    operation.check()
                    name = ctypes.wstring_at(attribute_pointer)
                    if ";range=" in name.casefold():
                        logger.warning(
                            "Windows LDAP returned a ranged attribute; this read is incomplete"
                        )
                        raise WindowsLdapError("unsupported ranged attribute", 92)
                    values = api.ldap_get_values_lenW(self._handle, entry, name)
                    if not values:
                        error = _ULONG()
                        self._require_success(
                            "attribute status",
                            int(
                                api.ldap_get_optionW(
                                    self._handle, 0x31, ctypes.byref(error)
                                )
                            ),
                        )
                        self._require_success("attribute values", int(error.value))
                    copied: list[bytes] = []
                    try:
                        index = 0
                        while values and values[index]:
                            operation.check()
                            value = values[index].contents
                            total_bytes += int(value.length)
                            if total_bytes > _MAX_ENTRY_BYTES:
                                logger.warning(
                                    "A Windows LDAP entry exceeds the 16 MiB read limit"
                                )
                                raise WindowsLdapError("entry size limit", 4)
                            copied.append(ctypes.string_at(value.data, value.length))
                            index += 1
                        attributes[name] = _Attribute(tuple(copied))
                    finally:
                        if values:
                            api.ldap_value_free_len(values)
                finally:
                    api.ldap_memfreeW(attribute_pointer)
                attribute_pointer = api.ldap_next_attributeW(
                    self._handle, entry, iterator
                )
        finally:
            if iterator:
                api.ber_free(iterator, 0)
        present = {name.casefold() for name in attributes}
        for name in requested:
            if name not in ("*", "+", "1.1") and name.casefold() not in present:
                # ldap3 exposes explicitly requested missing attributes with no
                # raw values. Preserve that shape for the existing converter.
                attributes[name] = _Attribute(())
        return WindowsDirectoryEntry(dn, attributes)

    def search(
        self,
        search_filter: str,
        attributes: list[str],
        base: str,
        scope: Literal["BASE", "LEVEL", "SUBTREE"],
        size_limit: int,
        paged_size: int,
    ) -> Generator[WindowsDirectoryEntry, None, None]:
        """Yield every page, preserving a final page even when it ends the search."""
        if active_proxy() is not None:
            logger.error("Native Windows LDAP cannot use a Python SOCKS proxy")
            raise ValueError("Native Windows LDAP cannot use a SOCKS proxy")
        if (
            not 1 <= self.port <= 65535
            or not 0 < paged_size < 2**32
            or not 0 <= size_limit < 2**32
        ):
            logger.error("Windows LDAP port or result limits are invalid")
            raise ValueError("Invalid Windows LDAP port or result limits")
        if any(
            "\x00" in value for value in (self.host, base, search_filter, *attributes)
        ):
            logger.error("Windows LDAP input contains an embedded null character")
            raise ValueError("Windows LDAP input may not contain null characters")
        with (
            self._own_search(),
            self.control.operation("Windows LDAP search", self._interrupt) as operation,
        ):
            try:
                self._open(operation)
                api = self._api
                assert api is not None
                requested = (_TEXT * (len(attributes) + 1))(*attributes, None)
                self._search = api.ldap_search_init_pageW(
                    self._handle,
                    base,
                    {"BASE": 0, "LEVEL": 1, "SUBTREE": 2}[scope],
                    search_filter,
                    requested,
                    0,
                    None,
                    None,
                    self._seconds(operation),
                    0,
                    None,
                )
                if not self._search:
                    raise WindowsLdapError(
                        "search initialization", int(api.LdapGetLastError())
                    )
                count = 0
                while True:
                    timeout = _Timeval(self._seconds(operation), 0)
                    results = _HANDLE()
                    estimated_count = _ULONG()
                    page_size = (
                        min(paged_size, size_limit - count)
                        if size_limit
                        else paged_size
                    )
                    code = int(
                        api.ldap_get_next_page_s(
                            self._handle,
                            self._search,
                            ctypes.byref(timeout),
                            page_size,
                            ctypes.byref(estimated_count),
                            ctypes.byref(results),
                        )
                    )
                    try:
                        entry = (
                            api.ldap_first_entry(self._handle, results)
                            if results
                            else None
                        )
                        while entry:
                            operation.check()
                            yield self._entry(entry, operation, attributes)
                            count += 1
                            if size_limit and count >= size_limit:
                                if code not in (
                                    _SUCCESS,
                                    _NO_MORE_RESULTS,
                                    _SIZE_LIMIT,
                                ):
                                    self._require_success("page", code)
                                logger.debug(
                                    "Windows LDAP reached the caller's selected result limit"
                                )
                                return
                            entry = api.ldap_next_entry(self._handle, entry)
                    finally:
                        if results:
                            api.ldap_msgfree(results)
                    if code == _NO_MORE_RESULTS:
                        logger.debug("Windows LDAP completed after %d entries", count)
                        return
                    # An empty successful page may still have a continuation.
                    self._require_success("page", code)
            finally:
                self._close()
