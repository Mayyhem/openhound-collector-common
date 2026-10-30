# Generalized from sccm/sccm/src/openhound_sccm/clients/wmi.py (the impacket
# DCOM + pywin32 win32com WMI backends, the WMI-instance → {Name: value} row
# normalizers, and the per-namespace DCOMConnection workaround) and the Go
# reference MSSQLHound/internal/wmi/wmi_windows.go (the Win32_GroupUser
# local-group member enumeration and the collector's Win32_Service →
# service-account fallback).
#
# "Generalize" per design spec §2.1: SCCM's WmiClient drove its auth off an
# implicit probe-ladder (http_auth.choose_auth) and only ever spoke to the SMS
# Provider namespace. This shared version instead takes an *explicit* auth
# selection (a WmiAuth dataclass, mirroring ad.py::LdapAuth) so the caller picks
# the credential up front, and adds the two MSSQL-shaped convenience queries the
# MSSQLHound port needs as *fallbacks*:
#   - service_account()      — Win32_Service.StartName (service-account fallback,
#     step 11; primary source is the SQL query sys.dm_server_services).
#   - local_group_members()  — Win32_GroupUser membership (step 18; the only
#     source for local Windows-group members).
"""WMI client for OpenHound collectors (impacket DCOM + pywin32 win32com).

:class:`WmiClient` owns a per-host WMI connection and runs WQL queries,
returning each instance as a plain ``{Name: value}`` dict. It is
service-agnostic — the caller supplies the WQL and (optionally) the namespace.

Authentication is one of (selected by which :class:`WmiAuth` field is set, in
priority order ticket → nt_hash → password → current-user SSPI):

  * **NTLM** with explicit ``username`` + ``password`` → impacket DCOM.
  * **NTLM pass-the-hash** with ``username`` + ``nt_hash`` → impacket DCOM.
  * **Kerberos pass-the-ticket** from a base64 KRB-CRED (``.kirbi``) → impacket
    DCOM with ``doKerberos=True`` and an exact HOST service ticket.
  * **Current-user SSPI** (Windows only) — the logged-on user's session via
    pywin32 ``win32com`` ``WbemScripting.SWbemLocator``. Gated behind
    ``sys.platform == "win32"`` + an import check (:func:`auth.sspi_available`).

DCOM always requires authentication, so there is no anonymous mode.
"""

from __future__ import annotations

import re
import socket
import sys
import time
from collections.abc import Callable
from threading import Lock, current_thread, get_ident, get_native_id
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Iterator, Optional

from ..logging.log_context import get_logger
from . import auth as auth_mod
from .auth import split_hashes, split_user_domain
from .auth import KerberosToken
from .kerberos import (
    CredentialInputError,
    KerberosAcquisitionError,
    KerberosCredentials,
    load_kerberos_credentials,
    validate_kerberos_identity,
    validate_secret_sources,
)
from .operations import (
    ClientCleanupError,
    ReadControl,
    ReadOperation,
    cancel_windows_call,
)
from .wmi_session import WmiHostLease
from .identity_errors import is_windows_credential_rejection
from ..collection import OperationResult
from ..discovery.network import active_network_settings
from ..proxy import active_proxy
from ..logging.authentication import authentication_diagnostics
from ..logging.console import SecretRedactor

logger = get_logger(__name__)

# Default WMI namespace for stock CIM classes (Win32_Service, Win32_GroupUser,
# Win32_ComputerSystem, …). Callers may override per query. Written in the
# backslash form impacket expects (it prepends ``\\<host>\``); the pywin32
# backend translates it to its ``//./<ns>`` form in _to_swbem_namespace().
DEFAULT_NAMESPACE = "root\\cimv2"

# Domains that name the LOCAL machine or built-in pseudo-authorities, not a real
# AD principal. Mirrors the Go reference's skip-list in wmi_windows.go so
# local_group_members() returns only domain members.
_LOCAL_AUTHORITIES = {"NT AUTHORITY", "NT SERVICE", "BUILTIN"}

# Parses a WMI object-path reference like
#   \\HOST\root\cimv2:Win32_UserAccount.Domain="MAYYHEM",Name="jdoe"
# into its Domain/Name pair (the PartComponent of a Win32_GroupUser row).
_REF_DOMAIN_NAME = re.compile(r'Domain="([^"]+)",Name="([^"]+)"')


@dataclass
class WmiAuth:
    """Which credential the WMI client connects with. Exactly one mode is
    selected by the first set field, in priority order:
    ticket → nt_hash → password → current-user SSPI.

    Mirrors :class:`openhound_collector_common.clients.ad.LdapAuth`.

    * ``username`` + ``password`` → impacket DCOM NTLM.
    * ``username`` + ``nt_hash`` (``LM:NT`` or bare 32-hex NT) → DCOM NTLM PtH.
    * ``kerberos_ticket`` (base64 KRB-CRED) → DCOM Kerberos pass-the-ticket.
    * none of the above → current-user SSPI (Windows) via pywin32.
    """

    username: Optional[str] = None
    password: Optional[str] = field(default=None, repr=False)
    nt_hash: Optional[str] = field(default=None, repr=False)
    kerberos_ticket: Optional[str] = field(default=None, repr=False)
    domain: str = ""  # default domain/realm for bare usernames
    kdc_host: Optional[str] = None  # KDC for Kerberos; defaults to the DC
    kerberos_ccache: str | None = field(default=None, repr=False)
    kerberos_keytab: str | None = field(default=None, repr=False)
    kerberos_realm: str | None = None
    kerberos_credentials: KerberosCredentials | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        validate_secret_sources(
            password=self.password,
            nt_hash=self.nt_hash,
            ticket=self.kerberos_ticket,
            ccache=self.kerberos_ccache,
            keytab=self.kerberos_keytab,
            loaded_credentials=self.kerberos_credentials,
        )
        if self.kerberos_credentials is not None:
            validate_kerberos_identity(
                self.kerberos_credentials, self.username, self.kerberos_realm
            )
        if (
            self.password is not None or self.nt_hash is not None
        ) and not self.username:
            logger.error("Explicit WMI password/hash authentication needs a username")
            raise CredentialInputError(
                "WMI password/hash authentication requires a username"
            )

    def uses_kerberos(self) -> bool:
        """Whether this selection requires Kerberos without an identity fallback."""
        return any(
            value is not None
            for value in (
                self.kerberos_ticket,
                self.kerberos_ccache,
                self.kerberos_keytab,
                self.kerberos_credentials,
                self.kerberos_realm,
            )
        )


# --- row normalization ----------------------------------------------------
# Both backends normalize a WMI instance to a plain ``{Name: value}`` dict.
# Embedded objects recurse to nested dicts/lists.


def _normalize(props: Any) -> dict:
    """impacket ``IWbemClassObject.getProperties()`` -> ``{Name: value}``."""
    out: dict[str, Any] = {}
    for name in props:
        out[name] = _unwrap(props[name].get("value"))
    return out


def _unwrap(value: Any) -> Any:
    if isinstance(value, list):
        # Arrays come back as Python lists; unwrap each element.
        return [_unwrap(v) for v in value]
    if hasattr(value, "getProperties"):
        # A directly-returned WMI object exposes getProperties(); recurse.
        return _normalize(value.getProperties())
    # An embedded WMI object comes back as an impacket ENCODING_UNIT whose
    # ObjectBlock must be parsed to expose its {name: {value: ...}} map.
    embedded = _embedded_props(value)
    if embedded is not None:
        return _normalize(embedded)
    # A scalar (str/int/None/…): pass through unchanged.
    return value


def _embedded_props(value: Any):
    """Return an embedded impacket ENCODING_UNIT's property map, or None."""
    try:
        object_block = value["ObjectBlock"]
    except (TypeError, KeyError, IndexError):
        # Not an ENCODING_UNIT (e.g. a plain scalar) — nothing to unwrap.
        return None
    parse = getattr(object_block, "parseObject", None)
    if parse is None:
        # No parser on the block — leave it raw.
        return None
    try:
        parse()
    except Exception as ex:  # noqa: BLE001 - undecodable embedded object: leave it raw
        logger.debug("WMI embedded object parse failed (left raw): %s", ex)
        return None
    if object_block.ctCurrent is None:
        # Parsed but produced no current type — nothing usable.
        return None
    return object_block.ctCurrent["properties"]


def _normalize_swbem(obj: Any) -> dict:
    """pywin32 SWbemObject -> ``{Name: value}``."""
    out: dict[str, Any] = {}
    for prop in obj.Properties_:
        out[prop.Name] = _unwrap_swbem(prop.Value)
    return out


def _unwrap_swbem(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        # SWbem arrays surface as tuples/lists; unwrap each element.
        return [_unwrap_swbem(v) for v in value]
    if hasattr(value, "Properties_"):
        # Embedded SWbemObjects expose Properties_; recurse into them.
        return _normalize_swbem(value)
    # A scalar: pass through unchanged.
    return value


# --- backends -------------------------------------------------------------


class _ImpacketBackend:
    """WMI over impacket DCOM: explicit creds, pass-the-hash, pass-the-ticket.

    impacket breaks if a second ``IWbemLevel1Login`` is issued over one
    ``DCOMConnection`` — the second namespace's queries fail with a bind-context
    rejection (validated live against the SCCM SMS Provider). So each WMI
    namespace gets a fresh ``DCOMConnection``. Only one is retained at a time,
    and the whole read owns a hostname lease through cleanup. Connections close
    after each result stream or complete-object read, so no idle connection or
    provider-wide keepalive thread survives between reads.
    """

    def __init__(
        self,
        target: str,
        *,
        domain: str,
        username: str,
        password: str,
        lmhash: str,
        nthash: str,
        do_kerberos: bool,
        kdc_host: Optional[str],
        tgt: Any = None,
        tgs: Any = None,
    ) -> None:
        self._target = target
        self._domain = domain
        self._username = username
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._do_kerberos = do_kerberos
        self._kdc_host = kdc_host
        self._tgt = tgt
        self._tgs = tgs
        # namespace -> (DCOMConnection, IWbemServices), one connection per namespace
        self._conns: dict[str, tuple] = {}
        self._lease = WmiHostLease(target)
        self.operation: ReadOperation | None = None
        self._connection_guard = Lock()
        self._owns_host = False
        self._owner_thread_name: str | None = None

    def connect(self) -> None:
        # Connections open lazily per namespace in _services_for(); a bad
        # credential raises there on the first query, so nothing eager here.
        return

    def _services_for(self, namespace: str):
        if self.operation is not None:
            self.operation.check()
        # Existing consumers do not select an operation budget.
        if self._conns and namespace not in self._conns:
            logger.debug("Closing the previous WMI namespace on %s", self._target)
            self.close()
        self._lease.acquire(self.operation)
        with self._connection_guard:
            self._owns_host = True
            self._owner_thread_name = current_thread().name
        if namespace not in self._conns:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dtypes import NULL

            dcom = DCOMConnection(
                self._target,
                self._username,
                self._password,
                self._domain,
                self._lmhash,
                self._nthash,
                "",
                self._tgt,
                self._tgs,
                # Each complete read closes its connection. There are no idle
                # references requiring the provider's process-wide ping timer.
                oxidResolver=False,
                doKerberos=self._do_kerberos,
                kdcHost=self._kdc_host,
            )
            iinterface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            login = wmi.IWbemLevel1Login(iinterface)
            svc = login.NTLMLogin(f"\\\\{self._target}\\{namespace}", NULL, NULL)
            login.RemRelease()
            self._conns[namespace] = (dcom, svc)
        if self.operation is not None:
            self.operation.check()
        return self._conns[namespace][1]

    def execquery(self, namespace: str, wql: str):
        """Open the namespace connection (raising on auth failure) and return the
        WMI enumerator for *wql*."""
        try:
            return self._services_for(namespace).ExecQuery(wql, lFlags=48)
        except BaseException:
            logger.warning(
                "WMI query setup failed on %s; closing its session", self._target
            )
            self.close()
            raise

    def stream(self, enum) -> Generator[dict, None, None]:
        """Yield normalized rows off a WMI enumerator until S_FALSE ends it."""
        try:
            while True:
                try:
                    if self.operation is not None:
                        self.operation.check()
                    # A finite provider wait lets the owning thread observe a stop.
                    objects = enum.Next(1000, 1)
                except Exception as ex:  # noqa: BLE001 - S_FALSE marks end of enumeration
                    if "S_FALSE" in str(ex):
                        break
                    if "WBEM_S_TIMEDOUT" in str(ex):
                        logger.debug(
                            "WMI on %s is still waiting for a result", self._target
                        )
                        continue
                    raise
                for obj in objects:
                    if self.operation is not None:
                        self.operation.check()
                    yield _normalize(obj.getProperties())
        finally:
            try:
                enum.RemRelease()
            finally:
                self.close()

    def read_instance(self, namespace: str, object_path: str) -> dict:
        """Read lazy object properties and release the DCOM object on this thread."""
        obj = None
        try:
            obj, _ = self._services_for(namespace).GetObject(object_path)
            if self.operation is not None:
                self.operation.check()
            return _normalize(obj.getProperties())
        finally:
            try:
                if obj is not None:
                    obj.RemRelease()
                # Failed setup did not produce an object to release.
            finally:
                self.close()

    def close(self) -> None:
        self._lease.check_owner()
        try:
            self.interrupt()
            # A failed constructor may have registered a connection before it
            # supplied a WMI service. Include that owned connection in cleanup.
            from impacket.dcerpc.v5.dcomrt import DCOMConnection, INTERFACE

            for dcom, _svc in self._conns.values():
                try:
                    dcom.disconnect()
                except Exception as error:
                    logger.warning(
                        "WMI disconnect from %s failed (%s)",
                        self._target,
                        type(error).__name__,
                    )
            self._conns.clear()
            with self._connection_guard:
                if self._owns_host:
                    DCOMConnection.PORTMAPS.pop(self._target, None)
                    DCOMConnection.OID_SET.pop(self._target, None)
                    INTERFACE.CONNECTIONS.pop(self._target, None)
                    self._owns_host = False
                # Never remove another client's provider state while waiting.
        except Exception as error:
            # Retain ownership if local cleanup failed. Releasing it here could
            # expose a still-live connection to another client's credentials.
            logger.error(
                "WMI local cleanup failed on %s (%s)",
                self._target,
                type(error).__name__,
            )
            raise ClientCleanupError("WMI local connection cleanup failed") from error
        self._lease.release()

    def interrupt(self) -> None:
        """Shut down only sockets belonging to this leased provider session."""
        from impacket.dcerpc.v5.dcomrt import DCOMConnection, INTERFACE

        with self._connection_guard:
            if not self._owns_host:
                return  # A waiting client must not stop the current host owner.
            connections = []
            portmap = DCOMConnection.PORTMAPS.get(self._target)
            if portmap is not None:
                connections.append(portmap)
            interfaces = INTERFACE.CONNECTIONS.get(self._target, {}).get(
                self._owner_thread_name, {}
            )
            connections.extend(value["dce"] for value in list(interfaces.values()))
            for connection in connections:
                transport = connection.get_rpc_transport()
                owned_socket = transport.get_socket()
                if owned_socket is not None:
                    try:
                        owned_socket.shutdown(socket.SHUT_RDWR)
                    except OSError as error:
                        logger.debug(
                            "WMI socket on %s was already closed (%s)",
                            self._target,
                            type(error).__name__,
                        )
                    finally:
                        owned_socket.close()
                # A constructor may not have created its socket yet. The owner
                # will check its stop condition as soon as that call returns.


class _PyWin32Backend:
    """WMI over pywin32 as the current Windows user (the SSPI rung; Windows-only)."""

    def __init__(self, target: str) -> None:
        self._target = target
        self._locator: Any = None
        self._services: dict[str, Any] = {}
        self._thread_id: int | None = None
        self._owns_com_initialization = False
        self._has_call_cancellation = False
        self._native_thread_id: int | None = None
        self.operation: ReadOperation | None = None

    def connect(self) -> None:
        """Initialize Windows on this worker before creating its WMI objects."""
        import pythoncom
        import win32com.client

        if active_proxy() is not None:
            logger.error("Current-user native WMI cannot use a Python SOCKS proxy")
            raise ValueError("Current-user native WMI cannot use a SOCKS proxy")
        if self._thread_id is not None:
            self._require_owner_thread()
            if self.operation is not None and not self._has_call_cancellation:
                pythoncom.CoEnableCallCancellation()
                self._has_call_cancellation = True
            logger.debug("Current-user WMI is already initialized for %s", self._target)
            return
        try:
            pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
        except pythoncom.error as error:
            # pywin32 documents the HRESULT as the first exception argument.
            # Reading it here also works with its published exception type stubs.
            hresult = error.args[0] if error.args else None
            if not isinstance(hresult, int) or (hresult & 0xFFFFFFFF) != 0x80010106:
                logger.error("Windows initialization for WMI failed: %s", error)
                raise
            # The caller already initialized this thread with another Windows
            # COM model. We can use it, but must not release its initialization.
            logger.debug(
                "Using the caller's existing Windows COM model for %s", self._target
            )
        else:
            self._owns_com_initialization = True
            logger.debug(
                "Initialized Windows COM on the WMI worker for %s", self._target
            )
        self._thread_id = get_ident()
        self._native_thread_id = get_native_id()
        try:
            if self.operation is not None:
                pythoncom.CoEnableCallCancellation()
                self._has_call_cancellation = True
            # Existing raw consumers keep their previous cancellation policy.
            self._locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        except Exception:
            logger.exception(
                "Could not create current-user WMI objects for %s", self._target
            )
            self.close()
            raise

    def _require_owner_thread(self) -> None:
        """Windows WMI objects and their cleanup stay on the connecting thread."""
        if self._thread_id != get_ident():
            logger.error(
                "Current-user WMI for %s must be used and closed on its connecting thread",
                self._target,
            )
            raise RuntimeError(
                "Current-user WMI must be used and closed on its connecting thread"
            )

    @staticmethod
    def _to_swbem_namespace(namespace: str) -> str:
        """Translate the canonical ``root\\cimv2`` form to pywin32's ``root\\cimv2``.

        ConnectServer takes the namespace with backslashes and the host
        separately, so we just normalize any leading ``//./`` / ``\\\\.\\`` that a
        caller might have passed; the bare ``root\\…`` form works as-is.
        """
        ns = namespace.replace("/", "\\")
        # Strip a leading local-host prefix (``\\.\``) if present.
        if ns.startswith("\\\\.\\"):
            ns = ns[4:]
        return ns

    def _services_for(self, namespace: str):
        self._require_owner_thread()
        if self.operation is not None:
            self.operation.check()
        if namespace not in self._services:
            ns = self._to_swbem_namespace(namespace)
            target = self._target
            network = active_network_settings()
            if network is not None and network.dns_server:
                target = str(
                    socket.getaddrinfo(
                        target, None, socket.AF_INET, socket.SOCK_STREAM
                    )[0][4][0]
                )
                logger.debug(
                    "Resolved native WMI destination through the selected DNS service"
                )
            # Otherwise Windows uses its normal resolver and invoking identity.
            # No user/password -> ConnectServer authenticates as the current user.
            self._services[namespace] = self._locator.ConnectServer(
                target, ns, "", "", "", "", 128 if self.operation is not None else 0
            )
        if self.operation is not None:
            self.operation.check()
        return self._services[namespace]

    def execquery(self, namespace: str, wql: str):
        return self._services_for(namespace).ExecQuery(wql, "WQL", 48)

    def stream(self, objset) -> Generator[dict, None, None]:
        self._require_owner_thread()
        for o in objset:
            if self.operation is not None:
                self.operation.check()
            yield _normalize_swbem(o)

    def read_instance(self, namespace: str, object_path: str) -> dict:
        """Read lazy object properties on the thread that owns Windows COM."""
        self._require_owner_thread()
        obj = self._services_for(namespace).Get(object_path)
        try:
            if self.operation is not None:
                self.operation.check()
            return _normalize_swbem(obj)
        finally:
            obj = (
                None  # Release the COM reference before this worker uninitializes COM.
            )

    def close(self) -> None:
        """Release WMI objects before balancing this worker's Windows initialization."""
        if self._thread_id is None:
            # Closing an unconnected/already closed backend has nothing to release.
            return
        self._require_owner_thread()
        self._services.clear()
        self._locator = None
        if self._has_call_cancellation:
            import pythoncom

            pythoncom.CoDisableCallCancellation()
            self._has_call_cancellation = False
        if self._owns_com_initialization:
            import pythoncom

            pythoncom.CoUninitialize()
            logger.debug(
                "Released the WMI worker's Windows initialization for %s", self._target
            )
        # A pre-existing caller initialization belongs to that caller.
        self._owns_com_initialization = False
        self._thread_id = None
        self._native_thread_id = None

    def interrupt(self) -> None:
        """Ask Windows to stop the owning thread's synchronous call."""
        if self._native_thread_id is not None:
            cancel_windows_call(self._native_thread_id)
        # There is no Windows call to cancel before initialization or after cleanup.


# --- client ---------------------------------------------------------------


class WmiClient:
    """Per-host WMI client: explicit-auth-selected, service-agnostic WQL runner."""

    def __init__(
        self,
        target: str,
        auth: Optional[WmiAuth] = None,
        *,
        read_control: ReadControl | None = None,
        on_query: Callable[[OperationResult], None] | None = None,
    ) -> None:
        self._target = target
        self._auth = auth or WmiAuth()
        self._backend: Any = None  # the connected backend, cached after connect()
        self._read_control = read_control
        self._operation: ReadOperation | None = None
        self._credential_failure: Exception | None = None
        self._cleanup_failure: ClientCleanupError | None = None
        self._read_guard = Lock()
        self._on_query = on_query
        self.last_query_result: OperationResult | None = None
        self._redactor = SecretRedactor(
            value
            for value in (
                self._auth.password,
                self._auth.nt_hash,
                self._auth.kerberos_ticket,
                self._auth.kerberos_ccache,
                self._auth.kerberos_keytab,
            )
            if value
        )
        # Existing callers keep their in-process backend and empty-on-failure behavior.

    # ----- auth selection -------------------------------------------------

    def _select_mode(self) -> str:
        """Pick the single auth mode from the supplied credential.

        Priority ticket → nt_hash → password → SSPI, matching ad.py::LdapAuth.
        """
        a = self._auth
        if a.uses_kerberos():
            # Pass-the-ticket → Kerberos only (no NTLM fallback, mirrors D12).
            logger.debug(
                "WMI on %s: selecting Kerberos (pass-the-ticket)", self._target
            )
            return "kerberos"
        if a.username and a.nt_hash:
            # Pass-the-hash → NTLM hash bind.
            logger.debug("WMI on %s: selecting NTLM pass-the-hash", self._target)
            return "ntlm_hash"
        if a.username and a.password is not None:
            # Explicit password → NTLM.
            logger.debug("WMI on %s: selecting NTLM (explicit password)", self._target)
            return "ntlm"
        # No explicit creds → current-user SSPI (Windows only).
        logger.debug("WMI on %s: selecting current-user SSPI", self._target)
        return "sspi"

    def _build_backend(self, mode: str):
        """Construct the WMI backend for the chosen auth mode.

        Raises ``RuntimeError`` for SSPI off-Windows / without pywin32, so the
        caller gets a clear message instead of an obscure import error deep in
        the connect path.
        """
        a = self._auth
        if mode == "sspi":
            if sys.platform != "win32" or not auth_mod.sspi_available():
                # SSPI is a Windows API; refuse early on other platforms / no pywin32.
                raise RuntimeError(
                    "WMI current-user SSPI requires Windows with pywin32; "
                    "supply --user/--password (or --nt-hash / --ticket) instead"
                )
            logger.debug(
                "Using the existing in-process current-user WMI backend for %s",
                self._target,
            )
            return _PyWin32Backend(self._target)

        # Explicit-cred DCOM paths share the impacket backend; only the hash /
        # Kerberos flags differ.
        ad_domain, sam = split_user_domain(a.username or "", a.domain)
        lm, nt = split_hashes(a.nt_hash)

        if mode == "ntlm":
            return _ImpacketBackend(
                self._target,
                domain=ad_domain,
                username=sam,
                password=a.password or "",
                lmhash="",
                nthash="",
                do_kerberos=False,
                kdc_host=a.kdc_host,
            )
        if mode == "ntlm_hash":
            return _ImpacketBackend(
                self._target,
                domain=ad_domain,
                username=sam,
                password="",
                lmhash=lm,
                nthash=nt,
                do_kerberos=False,
                kdc_host=a.kdc_host,
            )
        if mode == "kerberos":
            credentials = a.kerberos_credentials
            if credentials is None and any(
                value is not None
                for value in (
                    a.kerberos_ticket,
                    a.kerberos_ccache,
                    a.kerberos_keytab,
                )
            ):
                credentials = load_kerberos_credentials(
                    ticket=a.kerberos_ticket,
                    ccache_file=a.kerberos_ccache,
                    keytab_file=a.kerberos_keytab,
                    username=a.username,
                    realm=a.kerberos_realm,
                )
            realm = (
                credentials.realm
                if credentials is not None
                else (a.kerberos_realm or a.domain)
            )
            sam = credentials.username if credentials is not None else sam
            # RPC requests HOST/<target>. Select exactly that ticket locally;
            # passing a TGT would let the provider consult ambient cache state.
            tgs = KerberosToken(
                spn=f"HOST/{self._target}",
                realm=realm,
                username=sam,
                credentials=credentials,
                password=a.password if credentials is None else None,
                nt_hash=a.nt_hash if credentials is None else None,
                kdc_host=a.kdc_host,
            ).service_material()
            return _ImpacketBackend(
                # doKerberos treats `domain` as the realm; pass the full DNS domain.
                self._target,
                domain=realm,
                username=sam,
                password=a.password or "",
                lmhash=lm,
                nthash=nt,
                do_kerberos=True,
                kdc_host=a.kdc_host,
                tgs=tgs,
            )
        # Unreachable: _select_mode only returns the modes handled above.
        raise RuntimeError(f"WMI: unknown auth mode {mode!r}")

    # ----- connect / query ------------------------------------------------

    def connect(self) -> None:
        """Build and connect the selected backend on the calling thread."""
        if self._cleanup_failure is not None:
            logger.error(
                "The WMI client's earlier cleanup failed; refusing another read"
            )
            raise self._cleanup_failure
        if self._credential_failure is not None:
            logger.warning(
                "WMI credentials were already rejected; refusing another submission"
            )
            raise self._credential_failure
        if self._backend is not None:
            self._backend.operation = self._operation
            self._backend.connect()
            return  # The selected identity remains cached between reads.
        mode = self._select_mode()
        backend = self._build_backend(mode)
        backend.operation = self._operation
        self._backend = backend
        logger.verbose("WMI connecting to %s via %s", self._target, mode)
        try:
            backend.connect()
        except Exception as ex:  # noqa: BLE001 - surface connect failure to the caller
            logger.warning(
                "WMI connect to %s via %s failed: %s",
                self._target,
                mode,
                self._redactor.redact(str(ex)),
            )
            backend.close()
            self._backend = None
            raise
        logger.info("WMI connected to %s via %s", self._target, mode)
        self._backend = backend

    def _interrupt(self) -> None:
        if self._backend is not None:
            self._backend.interrupt()
        # The provider has no exposed connection before backend construction.

    @contextmanager
    def _reading(self, *, is_cleanup: bool = False) -> Iterator[None]:
        """Monitor through actual cleanup; never leave a provider running behind a future."""
        if not self._read_guard.acquire(blocking=False):
            logger.error("WMI client for %s already has an active read", self._target)
            raise RuntimeError("Use separate WMI clients for overlapping reads")
        try:
            with self._reading_owned(is_cleanup=is_cleanup):
                yield
        finally:
            self._read_guard.release()

    @contextmanager
    def _reading_owned(self, *, is_cleanup: bool = False) -> Iterator[None]:
        """Enter only while this client's single-read guard is held."""
        with authentication_diagnostics():
            if self._read_control is None:
                yield
                return  # Existing callers retain their previous timeout policy.
            operation = self._read_control.operation(
                f"WMI {'cleanup' if is_cleanup else 'read'} on {self._target}",
                self._interrupt,
                is_cleanup=is_cleanup,
            )
            with operation:
                self._operation = operation
                try:
                    yield
                finally:
                    if operation.is_stopped and self._backend is not None:
                        logger.warning(
                            "Closing the stopped WMI provider on its owning thread"
                        )
                        try:
                            self._backend.close()
                        except Exception as error:
                            logger.error(
                                "Stopped WMI cleanup failed on %s", self._target
                            )
                            raise ClientCleanupError(
                                "Stopped WMI cleanup failed"
                            ) from error
                        self._backend = None
                    self._operation = None

    def _remember_rejection(self, error: Exception) -> None:
        """Do not resubmit an identity after definite password/account rejection."""
        rejected = isinstance(
            error, (CredentialInputError, KerberosAcquisitionError)
        ) or is_windows_credential_rejection(error)
        if rejected:
            logger.warning(
                "WMI credentials were rejected; subsequent reads will not retry them"
            )
            self._credential_failure = RuntimeError(
                "WMI credentials were already rejected"
            )
        # Ordinary access, class or query errors do not establish a rejected identity.

    def query(self, wql: str, namespace: str = DEFAULT_NAMESPACE) -> list[dict]:
        """Run *wql* against *namespace* and return all rows as ``{Name: value}`` dicts.

        Existing callers return an empty list on failure. With read_control,
        keep complete rows received before failure and report the failed read
        through last_query_result and the optional callback. Windows may overrun
        its cancellation time; this method waits for actual provider cleanup.
        """
        logger.verbose("WMI query on %s (%s): %s", self._target, namespace, wql)
        return self._read(
            "WMI query",
            lambda: self._backend.stream(self._backend.execquery(namespace, wql)),
        )

    def read_instance(self, namespace: str, object_path: str) -> dict | None:
        """Read a complete object with the same budget and cleanup as a query."""

        def read() -> Generator[dict, None, None]:
            yield self._backend.read_instance(namespace, object_path)

        rows = self._read("WMI complete object", read)
        return rows[0] if rows else None

    def _read(
        self, label: str, produce: Callable[[], Generator[dict, None, None]]
    ) -> list[dict]:
        """Save one truthful completion outcome for a query or complete object."""
        started = time.monotonic()
        rows = []
        failure: str | None = None
        try:
            with self._reading():
                self.connect()
                stream = produce()
                try:
                    for row in stream:
                        if self._operation is not None:
                            self._operation.check()
                        rows.append(row)
                finally:
                    stream.close()
        except ClientCleanupError as error:
            self._cleanup_failure = error
            failure = "WMI cleanup failed"
            logger.error(
                "Native WMI cleanup failed for %s; the run must fail", self._target
            )
            raise
        except (KeyboardInterrupt, SystemExit):
            failure = "WMI read interrupted"
            logger.warning("WMI query on %s was interrupted", self._target)
            raise
        except Exception as ex:  # noqa: BLE001 - one query failing must not abort the rest
            failure = "WMI read failed; see the run logs"
            self._remember_rejection(ex)
            logger.warning(
                "WMI query on %s failed: %s",
                self._target,
                self._redactor.redact(str(ex)),
            )
            if self._read_control is None:
                rows = []
            # Opt-in monitored reads retain complete rows already received.
        finally:
            result = OperationResult(
                label,
                "failed" if failure else "completed",
                None if failure else len(rows),
                int((time.monotonic() - started) * 1000),
                failure,
            )
            self.last_query_result = result
            if self._on_query is not None:
                self._on_query(result)
            # Other consumers do not opt into saved query-outcome callbacks.
        logger.debug("WMI query on %s returned %d row(s)", self._target, len(rows))
        return rows

    # ----- convenience queries (MSSQLHound fallbacks) ---------------------

    def service_account(
        self, host: Optional[str] = None, service_like: str = "MSSQL%"
    ) -> Optional[str]:
        """Return the SQL engine service's ``StartName`` (logon account), or None.

        MSSQLHound's *primary* service-account source is the SQL query
        ``sys.dm_server_services``; this WMI lookup is the fallback (design §8
        step 11). *host* is accepted for symmetry/logging — the connection target
        was fixed at construction.

        ``Name LIKE 'MSSQL%'`` matches several services (e.g. the full-text
        ``MSSQLFDLauncher`` as well as the engine ``MSSQLSERVER`` / ``MSSQL$<inst>``).
        Their StartNames differ: the satellites run as local pseudo-accounts
        (``NT Service\\…`` / ``NT AUTHORITY\\…``) while the engine typically runs
        as the domain account we want. So we prefer the first match whose
        StartName is a *real* (non-pseudo) account, falling back to the first
        populated StartName when every match is a local pseudo-account.
        """
        wql = (
            f"SELECT Name,StartName FROM Win32_Service WHERE Name LIKE '{service_like}'"
        )
        rows = self.query(wql)
        fallback: Optional[str] = (
            None  # first populated StartName, used if no domain account found
        )
        for row in rows:
            start = row.get("StartName")
            if not start:
                # A matched service with no StartName (rare) — keep scanning.
                logger.debug(
                    "WMI service_account on %s: %s has no StartName",
                    self._target,
                    row.get("Name"),
                )
                continue
            domain_part = start.split("\\", 1)[0].upper() if "\\" in start else ""
            if domain_part not in _LOCAL_AUTHORITIES:
                # A real (domain or local-machine) account — this is the engine's
                # logon identity that MSSQLHound wants.
                logger.info(
                    "WMI service_account on %s: %s -> %s",
                    self._target,
                    row.get("Name"),
                    start,
                )
                return start
            # A local pseudo-account (NT SERVICE/NT AUTHORITY/BUILTIN); remember
            # the first one as a last-resort fallback and keep looking.
            logger.debug(
                "WMI service_account on %s: %s runs as pseudo-account %s (held as fallback)",
                self._target,
                row.get("Name"),
                start,
            )
            if fallback is None:
                fallback = start
        if fallback is not None:
            logger.info(
                "WMI service_account on %s: no domain account found; using %s",
                self._target,
                fallback,
            )
            return fallback
        logger.info(
            "WMI service_account on %s: no service matched %r",
            self._target,
            service_like,
        )
        return None

    def local_group_members(
        self, host: Optional[str] = None, group: Optional[str] = None
    ) -> list[dict]:
        """Enumerate local-group members via ``Win32_GroupUser``.

        Returns a list of ``{"domain": ..., "name": ...}`` dicts for members
        whose domain is NOT the local machine or a built-in pseudo-authority
        (NT AUTHORITY / NT SERVICE / BUILTIN) — i.e. the AD principals
        MSSQLHound cares about (design §8 step 18; Go wmi_windows.go). *host* is
        accepted for symmetry — the WMI target was fixed at construction.

        If *group* is given, only that group's members are returned (the
        ``GroupComponent`` is filtered server-side, as the Go code does);
        otherwise every local group's members are returned.
        """
        if group:
            # Filter to one group server-side. GroupComponent is a reference
            # whose Domain is the local computer's NetBIOS name; the Go code uses
            # the bare host short-name for that, so mirror it.
            local = self._target.split(".")[0]
            wql = (
                "SELECT GroupComponent,PartComponent FROM Win32_GroupUser "
                f"WHERE GroupComponent=\"Win32_Group.Domain='{local}',Name='{group}'\""
            )
            logger.verbose(
                "WMI local_group_members on %s: group=%s", self._target, group
            )
        else:
            # All local groups (caller filters / groups by GroupComponent).
            wql = "SELECT GroupComponent,PartComponent FROM Win32_GroupUser"
            logger.verbose("WMI local_group_members on %s: all groups", self._target)

        members: list[dict] = []
        for row in self.query(wql):
            part = row.get("PartComponent")
            if not part:
                # No member reference on this association row — skip it.
                logger.debug(
                    "WMI local_group_members on %s: row has no PartComponent",
                    self._target,
                )
                continue
            match = _REF_DOMAIN_NAME.search(str(part))
            if not match:
                # PartComponent didn't carry a Domain/Name pair we can parse.
                logger.debug(
                    "WMI local_group_members on %s: unparseable PartComponent %r",
                    self._target,
                    part,
                )
                continue
            member_domain, member_name = match.group(1), match.group(2)
            local_short = self._target.split(".")[0].upper()
            if (
                member_domain.upper() in _LOCAL_AUTHORITIES
                or member_domain.upper() == local_short
            ):
                # Local / built-in account, not an AD principal — skip (Go does the same).
                logger.debug(
                    "WMI local_group_members on %s: skipping local member %s\\%s",
                    self._target,
                    member_domain,
                    member_name,
                )
                continue
            logger.verbose(
                "WMI local_group_members on %s: domain member %s\\%s",
                self._target,
                member_domain,
                member_name,
            )
            members.append({"domain": member_domain, "name": member_name})
        logger.info(
            "WMI local_group_members on %s: %d domain member(s)",
            self._target,
            len(members),
        )
        return members

    def close(self) -> None:
        if self._backend is not None:
            try:
                with self._reading(is_cleanup=True):
                    self._backend.close()
                    self._backend = None
            except Exception as error:
                logger.error(
                    "WMI cleanup failed on %s (%s)", self._target, type(error).__name__
                )
                self._cleanup_failure = ClientCleanupError("WMI cleanup failed")
                raise self._cleanup_failure from error
