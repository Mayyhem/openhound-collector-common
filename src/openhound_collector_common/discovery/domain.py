"""Choose an AD DNS domain without trusting an arbitrary hostname suffix."""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass

import dns.exception
import dns.resolver

from ..logging import get_logger

logger = get_logger(__name__)
_DNS_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*", re.IGNORECASE)


@dataclass(frozen=True)
class DomainChoice:
    """A DNS domain and the source that supplied it, suitable for diagnostics."""

    name: str
    source: str


def _dns_domain(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    # This routine shape check has no collection consequence on its own.
    return value if _DNS_DOMAIN.fullmatch(value) else None


def _windows_domain(short_name: str | None = None) -> str | None:
    """Ask the Windows domain locator for its DNS name; direct operation only."""
    try:
        import win32security

        # DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME. pywin32 owns and
        # frees the Windows response buffer; no manually managed native pointer.
        result = win32security.DsGetDcName(
            domainName=short_name, flags=0x00000010 | 0x40000000
        )
        return _dns_domain(result["DomainName"])
    except Exception as error:
        logger.debug("Windows DNS domain detection failed: %s", error)
        return None


def detect_domain(
    *,
    explicit: str | None,
    usernames: Sequence[str | None],
    resolver: dns.resolver.Resolver,
    target_hosts: Sequence[str] = (),
    allow_public_dns: bool = False,
    allow_native_windows: bool = True,
) -> DomainChoice | None:
    """Choose explicit, credential, Windows, then verified target DNS information.

    A short Windows domain is translated through Windows only in direct mode.
    A target suffix needs an LDAP SRV record and private DC addresses unless the
    operator explicitly relaxes that private-address check. SQL-only collection
    can proceed when this returns None; AD discovery cannot.
    """
    if explicit:
        domain = _dns_domain(explicit)
        if domain:
            logger.debug("Using the explicitly selected AD DNS domain %s", domain)
            return DomainChoice(domain, "explicit domain")
        if sys.platform == "win32" and allow_native_windows:
            domain = _windows_domain(explicit)
            if domain:
                logger.info("Translated Windows domain %s to %s", explicit, domain)
                return DomainChoice(domain, "explicit Windows domain")
        logger.error("The selected domain is not an AD DNS domain: %s", explicit)
        raise ValueError("Use the AD DNS domain, such as --domain mayyhem.com")

    short_domain = None
    for username in usernames:
        if not username:
            # Missing credentials contribute no domain information.
            continue
        embedded = username.rsplit("@", 1)[-1] if "@" in username else username.partition("\\")[0] if "\\" in username else ""
        domain = _dns_domain(embedded)
        if domain:
            logger.info("Detected AD DNS domain %s from explicit credentials", domain)
            return DomainChoice(domain, "explicit credentials")
        if embedded and short_domain is None:
            # Keep the first qualified credential's domain for Windows translation.
            short_domain = embedded

    if sys.platform == "win32":
        current_short = os.environ.get("USERDOMAIN", "")
        current_dns = _dns_domain(os.environ.get("USERDNSDOMAIN", ""))
        if current_dns and (not short_domain or short_domain.casefold() == current_short.casefold()):
            logger.info("Detected AD DNS domain %s from the Windows sign-in", current_dns)
            return DomainChoice(current_dns, "Windows sign-in")
        if allow_native_windows:
            domain = _windows_domain(short_domain)
            if domain:
                logger.info("Detected AD DNS domain %s using Windows", domain)
                return DomainChoice(domain, "Windows domain locator")
        else:
            logger.debug("Proxy mode: native Windows domain discovery is disabled")

    for host in target_hosts:
        candidate = _dns_domain(host.partition(".")[2])
        if not candidate:
            # IPs and short hostnames do not assert AD membership.
            continue
        try:
            services = resolver.resolve(f"_ldap._tcp.{candidate}", "SRV")
            controllers = [str(item.target).rstrip(".") for item in services]
            addresses = [ipaddress.ip_address(str(address)) for controller in controllers for address in resolver.resolve(controller, "A")]
            if addresses and (allow_public_dns or all(address.is_private for address in addresses)):
                logger.info("Detected AD DNS domain %s from verified LDAP DNS records", candidate)
                return DomainChoice(candidate, "target and LDAP DNS records")
            logger.debug("Declining AD domain candidate %s: no permitted DC address", candidate)
        except (dns.exception.DNSException, ValueError) as error:
            logger.debug("AD DNS domain candidate %s was not verified: %s", candidate, error)
    logger.info("No AD DNS domain detected; explicit SQL targets can still be collected")
    return None
