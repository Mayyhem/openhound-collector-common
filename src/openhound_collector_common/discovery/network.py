"""Apply one run's DNS and proxy choices to Python network clients.

Native Windows providers are outside this boundary. Callers must disable those
providers in proxy mode rather than assume their traffic uses Python sockets.
"""

from __future__ import annotations

import ipaddress
import socket
import math
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Lock
from dataclasses import dataclass, field

import dns.resolver
import dns.exception

from ..logging import get_logger
from ..proxy.patch import socks_proxy_installed
from ..proxy.socks import parse_proxy_address
from .dns import make_resolver
from ..clients.operations import (
    ReadControl,
    ReadStoppedError,
    current_read_operation,
    socket_read,
)

logger = get_logger(__name__)
_SESSION_LOCK = Lock()
type SocketAddressInfo = tuple[
    socket.AddressFamily,
    socket.SocketKind,
    int,
    str,
    tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
]


@dataclass(frozen=True)
class NetworkSettings:
    """Explicit Python networking choices shared by this run's clients.

    Proxy URLs can contain credentials. This object is not saved run metadata;
    omit it from diagnostics.
    """

    proxy_address: str | None = field(default=None, repr=False)
    dns_server: str | None = None
    timeout: float = 5.0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.timeout, (int, float))
            or isinstance(self.timeout, bool)
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
            or (
                self.proxy_address is not None
                and not isinstance(self.proxy_address, str)
            )
            or (self.dns_server is not None and not isinstance(self.dns_server, str))
        ):
            logger.error("Invalid run network settings")
            raise ValueError(
                "Network settings require text addresses and a positive finite timeout"
            )


_ACTIVE_SETTINGS: NetworkSettings | None = None
_ACTIVE_RESOLVER: dns.resolver.Resolver | None = None


def active_network_settings() -> NetworkSettings | None:
    """Return the active run's immutable networking choices."""
    return _ACTIVE_SETTINGS


def active_resolver() -> dns.resolver.Resolver | None:
    """Return this run's selected resolver, including its proxy-aware TCP policy."""
    return _ACTIVE_RESOLVER


def resolve_socket_addresses(
    host: str, port: int, family: int = 0, kind: int = socket.SOCK_STREAM
) -> list[SocketAddressInfo]:
    """Resolve an owned read's endpoint through selected DNS and remaining time.

    Numeric addresses never need DNS. Without an opted-in read the existing
    socket resolver policy remains unchanged. A controlled standalone client
    gets its own bounded resolver when there is no run-wide network session.
    """
    operation = current_read_operation()
    if operation is None:
        return socket.getaddrinfo(host, port, family, kind)
    operation.check()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        resolver = active_resolver()
        if resolver is None:
            resolver = make_resolver(
                read_control=ReadControl(
                    min(5, operation.remaining()),
                    operation.deadline,
                    operation.stop_event,
                )
            )
        try:
            answers = resolver.resolve_name(
                host, family=family, lifetime=min(5, operation.remaining())
            )
        except dns.exception.DNSException as error:
            operation.check()
            logger.warning("Controlled endpoint DNS did not return an address")
            raise socket.gaierror(
                socket.EAI_NONAME, "Selected DNS did not resolve the endpoint"
            ) from error
        resolved = []
        for address, address_family in answers.addresses_and_families():
            resolved.extend(
                socket.getaddrinfo(
                    address, port, address_family, kind, flags=socket.AI_NUMERICHOST
                )
            )
        operation.check()
        return resolved
    # This path is a local numeric conversion, including under the DNS adapter.
    return socket.getaddrinfo(host, port, family, kind, flags=socket.AI_NUMERICHOST)


_SOCKET_LOOKUPS = (
    "getaddrinfo",
    "getnameinfo",
    "getfqdn",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
)


@contextmanager
def network_session(
    *,
    proxy_address: str | None = None,
    dns_server: str | None = None,
    domain_controller: str | None = None,
    timeout: float = 5.0,
    read_control: ReadControl | None = None,
) -> Iterator[dns.resolver.Resolver]:
    """Route Python clients through the selected resolver/proxy until workers stop.

    An explicit DNS server wins; an explicit DC is the next DNS choice. A DC
    hostname is looked up once using the configured DNS service, through TCP
    when proxied. A failed chosen resolver never falls back to local DNS.
    Only one session can run in a process, because both public adapters change
    Python's process-wide socket functions. Worker threads share that session.
    """
    global _ACTIVE_SETTINGS, _ACTIVE_RESOLVER
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        logger.error("DNS timeout must be greater than zero")
        raise ValueError("DNS timeout must be greater than zero")
    proxy = parse_proxy_address(proxy_address or "")
    if not _SESSION_LOCK.acquire(blocking=False):
        logger.error("A collector network session is already active")
        raise RuntimeError("A collector network session is already active")
    try:
        # Install proxy first so bootstrap DNS, including DC name resolution,
        # cannot accidentally leave through the machine's direct connection.
        with socks_proxy_installed(proxy, connect_timeout=timeout):
            if read_control is not None:
                resolver = make_resolver(
                    force_tcp=proxy is not None,
                    timeout=timeout,
                    lifetime=timeout,
                    read_control=read_control,
                )
            else:
                resolver = make_resolver(
                    force_tcp=proxy is not None, timeout=timeout, lifetime=timeout
                )
            chosen_server = dns_server or domain_controller
            if chosen_server:
                try:
                    ipaddress.ip_address(chosen_server)
                except ValueError:
                    logger.debug("Resolving DNS service hostname %s", chosen_server)
                    answers = resolver.resolve(chosen_server, "A")
                    chosen_server = str(answers[0])
                resolver.nameservers = [chosen_server]
                logger.info("Using DNS server %s", chosen_server)
            else:
                logger.debug("Using the host's configured DNS servers")
            resolver.cache = dns.resolver.Cache()
            _ACTIVE_SETTINGS = NetworkSettings(proxy_address, chosen_server, timeout)
            _ACTIVE_RESOLVER = resolver
            previous = {name: getattr(socket, name) for name in _SOCKET_LOOKUPS}
            # dnspython's documented adapter covers forward, reverse, and FQDN
            # lookups. Save actual previous functions: its restore method alone
            # would overwrite an outer proxy adapter with import-time defaults.
            dns.resolver.override_system_resolver(resolver)
            dns_getaddrinfo = socket.getaddrinfo

            def getaddrinfo(host, *args, **kwargs):
                if host is None or host in ("localhost", b"localhost"):
                    # Loopback and passive listeners belong to local DLT/tools.
                    return previous["getaddrinfo"](host, *args, **kwargs)
                return dns_getaddrinfo(host, *args, **kwargs)

            socket.getaddrinfo = getaddrinfo
            try:
                yield resolver
            finally:
                dns.resolver.restore_system_resolver()
                for name, original in previous.items():
                    setattr(socket, name, original)
                logger.debug("Restored DNS functions after collection")
    finally:
        _ACTIVE_SETTINGS = None
        _ACTIVE_RESOLVER = None
        _SESSION_LOCK.release()


def check_tcp_port(
    host: str, port: int, *, timeout: float, read_control: ReadControl | None = None
) -> None:
    """Check reachability through the active session; close the probe immediately.

    This establishes a TCP connection only. It sends no credentials and makes
    no claim that SQL authentication will succeed. Network failures propagate
    so the collector can record an incomplete target instead of an empty result.
    """
    if not host or not 1 <= port <= 65535 or timeout <= 0:
        logger.error("Invalid TCP reachability settings for host %r", host)
        raise ValueError(
            "Reachability needs a host, port 1..65535, and positive timeout"
        )
    try:
        if read_control is not None:
            _controlled_tcp_probe(host, port, timeout, read_control)
        else:
            with socket.create_connection((host, port), timeout=timeout):
                logger.debug("TCP port is reachable on %s:%d", host, port)
    except OSError as error:
        logger.warning("TCP port is unreachable on %s:%d: %s", host, port, error)
        raise


def _controlled_tcp_probe(
    host: str, port: int, timeout: float, control: ReadControl
) -> None:
    """Include DNS and every address attempt in one cancellable probe budget."""
    selected = ReadControl(
        min(timeout, control.timeout_seconds), control.deadline, control.stop_event
    )
    # DNS owns its bounded round-trip; socket_read owns each connect below.
    with selected.operation("TCP reachability", lambda: None) as operation:
        addresses = resolve_socket_addresses(host, port)
        operation.check()
        last_error: OSError | None = None
        for family, kind, protocol, canonical_name, address in addresses:
            operation.check()
            connection = socket.socket(family, kind, protocol)
            attempt = ReadControl(timeout, operation.deadline, operation.stop_event)
            try:
                with socket_read(attempt, "TCP reachability connection", connection):
                    connection.connect(address)
                logger.debug("TCP port is reachable on %s:%d", host, port)
                return
            except ReadStoppedError:
                logger.warning(
                    "TCP reachability stopped; no further address will be tried"
                )
                raise
            except OSError as error:
                last_error = error
                logger.debug(
                    "TCP reachability address attempt failed; checking remaining budget"
                )
        if last_error is not None:
            raise last_error
        logger.warning("TCP reachability received no usable address")
        raise OSError("TCP reachability received no usable address")
