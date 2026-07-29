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
    DCOM with ``doKerberos=True`` and an in-memory TGT.
  * **Current-user SSPI** (Windows only) — the logged-on user's session via
    pywin32 ``win32com`` ``WbemScripting.SWbemLocator``. Gated behind
    ``sys.platform == "win32"`` + an import check (:func:`auth.sspi_available`).

DCOM always requires authentication, so there is no anonymous mode.
"""
from __future__ import annotations

import base64
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from ..logging.log_context import get_logger
from . import auth as auth_mod
from .auth import split_hashes, split_user_domain

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
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    kerberos_ticket: Optional[str] = None  # base64 KRB-CRED (.kirbi)
    domain: str = ""                        # default domain/realm for bare usernames
    kdc_host: Optional[str] = None          # KDC for Kerberos; defaults to the DC


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
    namespace gets its own ``DCOMConnection`` (opened lazily, cached).
    """

    def __init__(self, target: str, *, domain: str, username: str, password: str,
                 lmhash: str, nthash: str, do_kerberos: bool, kdc_host: Optional[str],
                 tgt: Any = None, tgs: Any = None) -> None:
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

    def connect(self) -> None:
        # Connections open lazily per namespace in _services_for(); a bad
        # credential raises there on the first query, so nothing eager here.
        return

    def _services_for(self, namespace: str):
        if namespace not in self._conns:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dtypes import NULL
            dcom = DCOMConnection(
                self._target, self._username, self._password, self._domain,
                self._lmhash, self._nthash, "", self._tgt, self._tgs,
                oxidResolver=True, doKerberos=self._do_kerberos, kdcHost=self._kdc_host,
            )
            iinterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            login = wmi.IWbemLevel1Login(iinterface)
            svc = login.NTLMLogin(f"\\\\{self._target}\\{namespace}", NULL, NULL)
            login.RemRelease()
            self._conns[namespace] = (dcom, svc)
        return self._conns[namespace][1]

    def execquery(self, namespace: str, wql: str):
        """Open the namespace connection (raising on auth failure) and return the
        WMI enumerator for *wql*."""
        return self._services_for(namespace).ExecQuery(wql)

    def stream(self, enum) -> Iterator[dict]:
        """Yield normalized rows off a WMI enumerator until S_FALSE ends it."""
        try:
            while True:
                try:
                    obj = enum.Next(0xFFFFFFFF, 1)[0]
                except Exception as ex:  # noqa: BLE001 - S_FALSE marks end of enumeration
                    if "S_FALSE" in str(ex):
                        break
                    raise
                yield _normalize(obj.getProperties())
        finally:
            enum.RemRelease()

    def close(self) -> None:
        for dcom, _svc in self._conns.values():
            try:
                dcom.disconnect()
            except Exception as ex:  # noqa: BLE001 - best-effort teardown
                logger.debug("DCOM disconnect from %s failed: %s", self._target, ex)
        self._conns.clear()


class _PyWin32Backend:
    """WMI over pywin32 as the current Windows user (the SSPI rung; Windows-only)."""

    def __init__(self, target: str) -> None:
        self._target = target
        self._locator: Any = None
        self._services: dict[str, Any] = {}

    def connect(self) -> None:
        import win32com.client
        self._locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")

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
        if namespace not in self._services:
            ns = self._to_swbem_namespace(namespace)
            # No user/password -> ConnectServer authenticates as the current user.
            self._services[namespace] = self._locator.ConnectServer(self._target, ns)
        return self._services[namespace]

    def execquery(self, namespace: str, wql: str):
        return self._services_for(namespace).ExecQuery(wql)

    def stream(self, objset) -> Iterator[dict]:
        for o in objset:
            yield _normalize_swbem(o)

    def close(self) -> None:
        # pywin32 COM objects release on garbage collection; nothing to do.
        self._services.clear()


# --- client ---------------------------------------------------------------

class WmiClient:
    """Per-host WMI client: explicit-auth-selected, service-agnostic WQL runner."""

    def __init__(self, target: str, auth: Optional[WmiAuth] = None) -> None:
        self._target = target
        self._auth = auth or WmiAuth()
        self._backend: Any = None       # the connected backend, cached after connect()

    # ----- auth selection -------------------------------------------------

    def _select_mode(self) -> str:
        """Pick the single auth mode from the supplied credential.

        Priority ticket → nt_hash → password → SSPI, matching ad.py::LdapAuth.
        """
        a = self._auth
        if a.kerberos_ticket:
            # Pass-the-ticket → Kerberos only (no NTLM fallback, mirrors D12).
            logger.debug("WMI on %s: selecting Kerberos (pass-the-ticket)", self._target)
            return "kerberos"
        if a.username and a.nt_hash:
            # Pass-the-hash → NTLM hash bind.
            logger.debug("WMI on %s: selecting NTLM pass-the-hash", self._target)
            return "ntlm_hash"
        if a.username and a.password:
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
            return _PyWin32Backend(self._target)

        # Explicit-cred DCOM paths share the impacket backend; only the hash /
        # Kerberos flags differ.
        ad_domain, sam = split_user_domain(a.username or "", a.domain)
        lm, nt = split_hashes(a.nt_hash)

        if mode == "ntlm":
            return _ImpacketBackend(
                self._target, domain=ad_domain, username=sam, password=a.password or "",
                lmhash="", nthash="", do_kerberos=False, kdc_host=a.kdc_host,
            )
        if mode == "ntlm_hash":
            return _ImpacketBackend(
                self._target, domain=ad_domain, username=sam, password="",
                lmhash=lm, nthash=nt, do_kerberos=False, kdc_host=a.kdc_host,
            )
        if mode == "kerberos":
            tgt = None
            if a.kerberos_ticket:
                ticket_user, tgt = self._load_ticket()
                # Pass-the-ticket may supply no -u; impacket still needs a client
                # principal for the AP-REQ, so derive it from the ticket's cname.
                if not sam:
                    sam = ticket_user
            return _ImpacketBackend(
                # doKerberos treats `domain` as the realm; pass the full DNS domain.
                self._target, domain=a.domain, username=sam, password=a.password or "",
                lmhash=lm, nthash=nt, do_kerberos=True, kdc_host=a.kdc_host, tgt=tgt,
            )
        # Unreachable: _select_mode only returns the modes handled above.
        raise RuntimeError(f"WMI: unknown auth mode {mode!r}")

    def _load_ticket(self):
        """Load a base64 KRB-CRED (.kirbi) into ``(username, TGT)`` for impacket.

        The client principal is read from the ticket so pass-the-ticket works
        even when no ``--user`` was supplied.
        """
        from impacket.krb5.ccache import CCache
        ccache = CCache()
        ccache.fromKRBCRED(base64.b64decode(self._auth.kerberos_ticket, validate=True))
        if not ccache.credentials:
            raise ValueError("--ticket contains no usable credentials")
        cred = ccache.credentials[0]
        username = cred["client"].prettyPrint().decode("utf-8", "replace").split("@")[0]
        # impacket's DCOMConnection requests the DCOM service ticket from the TGT.
        return username, cred.toTGT()

    # ----- connect / query ------------------------------------------------

    def connect(self) -> None:
        """Build and connect the selected backend (cached). Idempotent."""
        if self._backend is not None:
            return
        mode = self._select_mode()
        backend = self._build_backend(mode)
        logger.verbose("WMI connecting to %s via %s", self._target, mode)
        try:
            backend.connect()
        except Exception as ex:  # noqa: BLE001 - surface connect failure to the caller
            logger.warning("WMI connect to %s via %s failed: %s", self._target, mode, ex)
            backend.close()
            raise
        logger.info("WMI connected to %s via %s", self._target, mode)
        self._backend = backend

    def query(self, wql: str, namespace: str = DEFAULT_NAMESPACE) -> list[dict]:
        """Run *wql* against *namespace* and return all rows as ``{Name: value}`` dicts.

        Connects on first use. Returns ``[]`` (and logs a warning) if the query
        fails, so one bad class doesn't abort the caller's collection.
        """
        try:
            self.connect()
        except Exception as ex:  # noqa: BLE001 - connect failed; no rows to return
            logger.warning("WMI query on %s skipped (connect failed): %s", self._target, ex)
            return []
        logger.verbose("WMI query on %s (%s): %s", self._target, namespace, wql)
        try:
            raw = self._backend.execquery(namespace, wql)
            rows = list(self._backend.stream(raw))
        except Exception as ex:  # noqa: BLE001 - one query failing must not abort the rest
            logger.warning("WMI query on %s failed: %s", self._target, ex)
            return []
        logger.debug("WMI query on %s returned %d row(s)", self._target, len(rows))
        return rows

    # ----- convenience queries (MSSQLHound fallbacks) ---------------------

    def service_account(self, host: Optional[str] = None, service_like: str = "MSSQL%") -> Optional[str]:
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
            "SELECT Name,StartName FROM Win32_Service "
            f"WHERE Name LIKE '{service_like}'"
        )
        rows = self.query(wql)
        fallback: Optional[str] = None  # first populated StartName, used if no domain account found
        for row in rows:
            start = row.get("StartName")
            if not start:
                # A matched service with no StartName (rare) — keep scanning.
                logger.debug("WMI service_account on %s: %s has no StartName",
                             self._target, row.get("Name"))
                continue
            domain_part = start.split("\\", 1)[0].upper() if "\\" in start else ""
            if domain_part not in _LOCAL_AUTHORITIES:
                # A real (domain or local-machine) account — this is the engine's
                # logon identity that MSSQLHound wants.
                logger.info("WMI service_account on %s: %s -> %s",
                            self._target, row.get("Name"), start)
                return start
            # A local pseudo-account (NT SERVICE/NT AUTHORITY/BUILTIN); remember
            # the first one as a last-resort fallback and keep looking.
            logger.debug("WMI service_account on %s: %s runs as pseudo-account %s (held as fallback)",
                         self._target, row.get("Name"), start)
            if fallback is None:
                fallback = start
        if fallback is not None:
            logger.info("WMI service_account on %s: no domain account found; using %s", self._target, fallback)
            return fallback
        logger.info("WMI service_account on %s: no service matched %r", self._target, service_like)
        return None

    def local_group_members(self, host: Optional[str] = None,
                            group: Optional[str] = None) -> list[dict]:
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
            logger.verbose("WMI local_group_members on %s: group=%s", self._target, group)
        else:
            # All local groups (caller filters / groups by GroupComponent).
            wql = "SELECT GroupComponent,PartComponent FROM Win32_GroupUser"
            logger.verbose("WMI local_group_members on %s: all groups", self._target)

        members: list[dict] = []
        for row in self.query(wql):
            part = row.get("PartComponent")
            if not part:
                # No member reference on this association row — skip it.
                logger.debug("WMI local_group_members on %s: row has no PartComponent", self._target)
                continue
            match = _REF_DOMAIN_NAME.search(str(part))
            if not match:
                # PartComponent didn't carry a Domain/Name pair we can parse.
                logger.debug("WMI local_group_members on %s: unparseable PartComponent %r",
                             self._target, part)
                continue
            member_domain, member_name = match.group(1), match.group(2)
            local_short = self._target.split(".")[0].upper()
            if member_domain.upper() in _LOCAL_AUTHORITIES or member_domain.upper() == local_short:
                # Local / built-in account, not an AD principal — skip (Go does the same).
                logger.debug("WMI local_group_members on %s: skipping local member %s\\%s",
                             self._target, member_domain, member_name)
                continue
            logger.verbose("WMI local_group_members on %s: domain member %s\\%s",
                           self._target, member_domain, member_name)
            members.append({"domain": member_domain, "name": member_name})
        logger.info("WMI local_group_members on %s: %d domain member(s)", self._target, len(members))
        return members

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()
            self._backend = None
