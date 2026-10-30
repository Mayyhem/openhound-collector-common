"""Resolve a PTR-less DC without guessing or selecting a different server."""

from types import SimpleNamespace

import dns.resolver

from openhound_collector_common.discovery.dns import dc_hostname_for_address
from openhound_collector_common.clients import ad


class Resolver:
    def __init__(self):
        self.queries = []

    def resolve(self, name, record):
        self.queries.append((name, record))
        if record == "SRV":
            return [
                SimpleNamespace(target="other.example.com."),
                SimpleNamespace(target="chosen.example.com."),
            ]
        return ["10.10.10.101" if name.startswith("other") else "10.10.10.100"]


def test_srv_name_must_forward_resolve_to_the_explicit_dc_address():
    resolver = Resolver()
    assert (
        dc_hostname_for_address("example.com", "10.10.10.100", resolver=resolver)
        == "chosen.example.com"
    )
    assert resolver.queries == [
        ("_ldap._tcp.dc._msdcs.example.com", "SRV"),
        ("other.example.com", "A"),
        ("chosen.example.com", "A"),
    ]


def test_a_different_dc_is_not_an_acceptable_substitute():
    assert (
        dc_hostname_for_address("example.com", "10.10.11.100", resolver=Resolver())
        is None
    )


def test_selected_dns_failure_never_uses_system_resolver():
    class FailedResolver:
        def resolve(self, *args):
            raise dns.resolver.NXDOMAIN()

    assert (
        dc_hostname_for_address(
            "example.com", "10.10.10.100", resolver=FailedResolver()
        )
        is None
    )


def test_explicit_kerberos_uses_the_active_resolver_when_ptr_is_absent(monkeypatch):
    monkeypatch.setattr(ad, "_reverse_dns_hostname", lambda value: None)
    resolver = Resolver()
    monkeypatch.setattr(ad, "active_resolver", lambda: resolver)
    client = ad.AdClient(
        "example.com", "10.10.10.100", ad.LdapAuth(kerberos_ticket="opaque-ticket")
    )
    plan = [SimpleNamespace(auth_mode="kerberos")]
    attempts, hostname = client._prepare_attempts_and_host(plan)
    assert attempts == plan and hostname == "chosen.example.com"
