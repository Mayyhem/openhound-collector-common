# Generalized from sccm/sccm/src/openhound_sccm/collectors/dns.py (the resolver
# override + SRV/A discovery helpers) and the Go reference
# MSSQLHound/cmd/mssqlhound/main.go (`--dc` auto-resolve: SRV `_ldap._tcp.<domain>`
# first, A-record of the domain as fallback) and MSSQLHound/internal/ad/client.go
# `resolveDomainController` / the `--dns-resolver` override in `NewClient`.
#
# "Generalize" per design spec §2.1: the SCCM collector only ever resolved
# management-point SRV records inline inside a dlt resource; here we lift the
# generic pieces (a configurable dnspython resolver + domain-controller
# discovery) into reusable functions with no SCCM/MSSQL specifics. The proxy-
# aware angle mirrors the Go `SetProxyDialer` rebuild that forces DNS over TCP
# through the SOCKS5 proxy, exposed here as an optional knob.
"""DNS-based discovery helpers for OpenHound collectors.

Two public pieces:

- :func:`resolve_dc` — find a domain controller hostname for a domain. If the
  caller already knows the DC it is returned unchanged; otherwise we ask DNS for
  the ``_ldap._tcp.<domain>`` SRV record (the canonical "where are my DCs" query
  every domain-joined machine uses) and fall back to the domain's own A record.
- :func:`make_resolver` — build a :class:`dns.resolver.Resolver` pointed at a
  specific nameserver IP, optionally forcing TCP (needed when the lookups are
  tunneled through a SOCKS5 proxy, which cannot carry UDP).

Uses ``dnspython``. Stdlib ``socket`` is used only for the final A-record
fallback so we get the host's effective resolver behavior for the plain case.
"""

from __future__ import annotations

import logging
import socket
import ipaddress
from threading import Event
from typing import Optional

import dns.exception
import dns.resolver
from ..clients.operations import ReadControl, current_read_operation

logger = logging.getLogger(__name__)

# Match the timeouts the SCCM dns collector used so behavior is consistent
# across collectors: 5s per query, 10s total budget including retries.
_DEFAULT_TIMEOUT = 5.0
_DEFAULT_LIFETIME = 10.0


def dc_hostname_for_address(
    domain: str,
    address: str,
    *,
    resolver: dns.resolver.Resolver,
) -> str | None:
    """Find a published DC hostname whose forward DNS includes the selected IP.

    Some domains have no PTR records. Kerberos still needs the DC's registered
    hostname. Use AD's SRV records and verify the candidate's A/AAAA records;
    never substitute a different DC or invent a name from a short domain label.
    Every query uses the caller's selected resolver and its TCP/proxy policy.
    """
    selected = ipaddress.ip_address(address)
    if not domain or "." not in domain:
        logger.warning("A DNS domain is needed to find a DC hostname without PTR")
        return None
    try:
        entries = resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
    except dns.exception.DNSException as error:
        logger.warning("Cannot read published DC names for %s: %s", domain, error)
        return None
    record_type = "A" if selected.version == 4 else "AAAA"
    for entry in entries:
        candidate = str(getattr(entry, "target", "")).rstrip(".")
        if not candidate:
            logger.warning("Ignoring a DC service record without a hostname")
            continue
        try:
            addresses = resolver.resolve(candidate, record_type)
        except dns.exception.DNSException as error:
            logger.debug("Cannot verify published DC name %s: %s", candidate, error)
            continue
        if any(ipaddress.ip_address(str(value)) == selected for value in addresses):
            logger.info(
                "Verified DC hostname %s for the selected address %s",
                candidate,
                address,
            )
            return candidate
        logger.debug("Published DC name %s belongs to a different address", candidate)
    logger.warning(
        "No published DC hostname resolves to the selected address %s", address
    )
    return None


def make_resolver(
    server_ip: Optional[str] = None,
    *,
    force_tcp: bool = False,
    timeout: float = _DEFAULT_TIMEOUT,
    lifetime: float = _DEFAULT_LIFETIME,
    read_control: ReadControl | None = None,
) -> dns.resolver.Resolver:
    """Build a dnspython resolver, optionally overriding the nameserver.

    *server_ip* — when set, every query goes to this nameserver IP only (the
    ``--dns-resolver`` knob). When ``None`` the host's configured resolvers are
    used (``dns.resolver.Resolver()`` reads ``/etc/resolv.conf`` / the Windows
    DNS client config).

    *force_tcp* — send queries over TCP instead of UDP. Set this when DNS is
    tunneled through a SOCKS5 proxy: SOCKS5 has no UDP ASSOCIATE in our dialer,
    and DNS works fine over TCP. Mirrors the Go ``SetProxyDialer`` rebuild that
    forces ``"tcp"`` for the proxied resolver.
    """
    if server_ip:
        # Explicit nameserver: don't read the host config at all, so a wrong
        # local resolver can't shadow the operator's choice.
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server_ip]
        logger.debug("make_resolver: using explicit nameserver %s", server_ip)
    else:
        # No override: inherit the host's resolver configuration.
        resolver = dns.resolver.Resolver()
        logger.debug("make_resolver: using host-configured nameservers")
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    if force_tcp or read_control is not None:
        # SOCKS5 (our dialer) can't carry UDP, so proxied DNS must use TCP.
        # dnspython takes tcp per-call, so wrap resolve() to default it on.
        # Mirrors the Go SetProxyDialer rebuild that forces "tcp".
        _orig_resolve = resolver.resolve

        def _resolve_tcp(qname, *args, **kwargs):
            positional = list(args)
            if len(positional) >= 3:
                positional[2] = True
                kwargs.pop("tcp", None)
            else:
                kwargs["tcp"] = True
            return _orig_resolve(qname, *positional, **kwargs)

        def _resolve_controlled(
            qname,
            rdtype="A",
            rdclass="IN",
            tcp=False,
            source=None,
            raise_on_no_answer=True,
            source_port=0,
            lifetime=None,
            search=None,
        ):
            selected_tcp = force_tcp or tcp
            assert read_control is not None
            parent = current_read_operation()
            selected = read_control
            if parent is not None:
                parent.check()
                selected = ReadControl(
                    min(read_control.timeout_seconds, parent.remaining()),
                    parent.deadline,
                    parent.stop_event,
                )
            notice = Event()

            def request_stop() -> None:
                if not notice.is_set():
                    logger.warning(
                        "DNS stop requested; waiting for the bounded in-flight lookup"
                    )
                    notice.set()
                # dnspython owns these short-lived sockets. Its public lifetime
                # bounds the round trip; never close an unowned provider handle.

            operation = selected.operation("DNS lookup", request_stop)
            with operation:
                budget = operation.remaining()
                if lifetime is not None:
                    budget = min(budget, lifetime)
                try:
                    result = _orig_resolve(
                        qname,
                        rdtype,
                        rdclass,
                        selected_tcp,
                        source,
                        raise_on_no_answer,
                        source_port,
                        budget,
                        search,
                    )
                except Exception:
                    operation.check()
                    raise  # Preserve genuine NXDOMAIN/transport failures.
                operation.check()
                return result

        # Per-instance override, deliberately: it forces TCP for this resolver only,
        # leaving dnspython's class untouched for anything else in the process.
        resolver.resolve = (  # type: ignore[method-assign]
            _resolve_controlled if read_control is not None else _resolve_tcp
        )
        logger.debug(
            "make_resolver: selected DNS controls (TCP=%s, bounded=%s)",
            force_tcp,
            read_control is not None,
        )
    return resolver


def resolve_dc(
    domain: str,
    dc: Optional[str] = None,
    *,
    resolver: Optional[dns.resolver.Resolver] = None,
) -> str:
    """Return a domain-controller hostname for *domain*.

    Resolution order (mirrors Go ``mssqlhound`` ``--dc`` auto-resolve):

    1. If *dc* is supplied (the ``--dc`` flag), it wins outright — returned
       unchanged, no DNS performed.
    2. Otherwise query the ``_ldap._tcp.<domain>`` SRV record. Every AD domain
       publishes one SRV target per DC; we take the first target hostname.
    3. If no SRV answer, fall back to treating the *domain* name itself as a
       host (its A record) — works for single-DC labs where the domain FQDN
       resolves straight to the DC.

    Always returns a string: the resolved DC host, or — if every lookup fails —
    the bare *domain* (so the caller's LDAP transport waterfall can still try
    it directly and surface a concrete connect error). Never raises for a DNS
    miss; raises ``ValueError`` only if neither *dc* nor *domain* is provided.
    """
    if dc:
        # Operator pinned the DC explicitly — honor it, skip discovery.
        logger.debug("resolve_dc: using caller-supplied DC %s", dc)
        return dc
    if not domain:
        # Nothing to resolve from. This is a programming/config error, not a
        # transient DNS failure, so it's worth raising rather than guessing.
        raise ValueError("resolve_dc requires either an explicit dc or a domain")

    res = resolver or make_resolver()

    srv_name = f"_ldap._tcp.{domain}"
    try:
        answers = res.resolve(srv_name, "SRV")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        # No SRV record published — common outside a real AD domain. Fall
        # through to the A-record fallback below.
        logger.debug(
            "resolve_dc: no SRV record for %s (%s)", srv_name, type(exc).__name__
        )
        answers = None
    except dns.exception.Timeout:
        # The nameserver didn't answer in time; fall back rather than abort.
        logger.warning(
            "resolve_dc: SRV query for %s timed out; trying A-record fallback", srv_name
        )
        answers = None
    except dns.exception.DNSException as exc:
        # Any other dnspython error (e.g. no nameservers configured) — log and
        # fall back so a single bad SRV lookup doesn't kill discovery.
        logger.warning(
            "resolve_dc: SRV query for %s failed: %s; trying A-record fallback",
            srv_name,
            exc,
        )
        answers = None

    if answers is not None:
        # Pick the first SRV target with a non-empty hostname.
        for rdata in answers:
            target = str(getattr(rdata, "target", "")).rstrip(".")
            if target:
                logger.info("resolve_dc: resolved DC %s via SRV %s", target, srv_name)
                return target
        # SRV answered but every target was empty — unusual; fall through.
        logger.debug(
            "resolve_dc: SRV %s returned no usable target; trying A-record fallback",
            srv_name,
        )

    # A-record fallback: does the domain name itself resolve to a host?
    if _domain_resolves(domain, res):
        logger.info("resolve_dc: falling back to domain name as DC host %s", domain)
        return domain

    # Everything failed. Return the domain so the LDAP waterfall still has
    # something to try (and produces a concrete, debuggable connect error).
    logger.warning(
        "resolve_dc: could not resolve a DC for %s via SRV or A record; "
        "returning the domain name verbatim",
        domain,
    )
    return domain


def _domain_resolves(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """True if *domain* has an A/AAAA record (so it can be used as a DC host).

    Tries dnspython first (honors a ``--dns-resolver`` override), then a plain
    stdlib ``getaddrinfo`` so an explicit-resolver miss still benefits from the
    host's own resolution as a last resort.
    """
    try:
        resolver.resolve(domain, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # No A record via the configured resolver — try the host resolver next.
        logger.debug("_domain_resolves: no A record for %s via dnspython", domain)
    except dns.exception.DNSException as exc:
        # Timeout / config error — fall through to the stdlib attempt.
        logger.debug(
            "_domain_resolves: dnspython A lookup for %s failed: %s", domain, exc
        )

    if "resolve" in resolver.__dict__:
        # A selected TCP/bounded resolver owns the lookup policy. A local
        # getaddrinfo fallback could bypass either its route or its deadline.
        logger.debug(
            "_domain_resolves: keeping selected resolver policy for %s", domain
        )
        return False
    try:
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, OSError) as exc:
        # Host resolver also can't find it -- the domain truly doesn't resolve.
        logger.debug(
            "_domain_resolves: stdlib getaddrinfo for %s failed: %s", domain, exc
        )
        return False


__all__ = ["make_resolver", "resolve_dc"]
