"""Exercise domain precedence without contacting AD or trusting public suffixes."""

from types import SimpleNamespace

import dns.resolver
import pytest

from openhound_collector_common.discovery import domain


class Resolver:
    """Return only the LDAP DNS records selected by each case."""

    def __init__(self, *, address="10.10.10.100", missing=False):
        self.address = address
        self.missing = missing
        self.queries = []

    def resolve(self, name, kind):
        self.queries.append((name, kind))
        if self.missing:
            raise dns.resolver.NXDOMAIN()
        if kind == "SRV":
            return [SimpleNamespace(target="dc.mayyhem.com.")]
        return [self.address]


@pytest.fixture(autouse=True)
def no_actual_windows_discovery(monkeypatch):
    monkeypatch.setattr(domain.sys, "platform", "linux")
    monkeypatch.setattr(domain, "_windows_domain", lambda *args: None)


@pytest.mark.parametrize(
    "explicit,user,expected,source",
    [
        ("MAYYHEM.COM.", "user@different.invalid", "mayyhem.com", "explicit domain"),
        (None, "user@mayyhem.com", "mayyhem.com", "explicit credentials"),
        (None, "mayyhem.com\\user", "mayyhem.com", "explicit credentials"),
    ],
)
def test_explicit_and_credential_domains_need_no_dns(explicit, user, expected, source):
    resolver = Resolver(missing=True)
    result = domain.detect_domain(explicit=explicit, usernames=[user], resolver=resolver)
    assert result == domain.DomainChoice(expected, source)
    assert resolver.queries == []


def test_short_windows_domain_does_not_become_a_fake_dns_domain():
    assert domain.detect_domain(explicit=None, usernames=["MAYYHEM\\user"], resolver=Resolver()) is None
    with pytest.raises(ValueError, match="AD DNS domain"):
        domain.detect_domain(explicit="MAYYHEM", usernames=[], resolver=Resolver())


def test_windows_sign_in_does_not_override_a_different_credential_domain(monkeypatch):
    monkeypatch.setattr(domain.sys, "platform", "win32")
    monkeypatch.setenv("USERDOMAIN", "MAYYHEM")
    monkeypatch.setenv("USERDNSDOMAIN", "mayyhem.com")
    assert domain.detect_domain(explicit=None, usernames=["OTHER\\user"], resolver=Resolver(), allow_native_windows=False) is None
    assert domain.detect_domain(explicit=None, usernames=["MAYYHEM\\user"], resolver=Resolver(), allow_native_windows=False).name == "mayyhem.com"


def test_proxy_mode_does_not_call_native_windows_domain_locator(monkeypatch):
    monkeypatch.setattr(domain.sys, "platform", "win32")
    monkeypatch.delenv("USERDNSDOMAIN", raising=False)

    def forbidden(*args):
        raise AssertionError("Native Windows discovery must stay off in proxy mode")

    monkeypatch.setattr(domain, "_windows_domain", forbidden)
    assert domain.detect_domain(explicit=None, usernames=[], resolver=Resolver(), allow_native_windows=False) is None


@pytest.mark.parametrize(
    "address,allow_public,missing,expected",
    [("10.10.10.100", False, False, "mayyhem.com"), ("8.8.8.8", False, False, None), ("8.8.8.8", True, False, "mayyhem.com"), ("10.10.10.100", False, True, None)],
)
def test_target_suffix_requires_verified_ldap_dns(address, allow_public, missing, expected):
    result = domain.detect_domain(explicit=None, usernames=[], target_hosts=["ps1-db.mayyhem.com"], resolver=Resolver(address=address, missing=missing), allow_public_dns=allow_public)
    assert (result.name if result else None) == expected
