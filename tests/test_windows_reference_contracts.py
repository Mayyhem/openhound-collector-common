"""Pinned Windows reference values through the selected shared Python boundary."""

import dns.resolver

from openhound_collector_common.clients.ad import AdClient, bytes_to_sid
from openhound_collector_common.discovery.domain import detect_domain


def test_go_domain_to_dn_includes_the_real_domain_normalization_boundary():
    resolver = dns.resolver.Resolver(configure=False)
    for domain, expected in (
        ("corp.example.com", "DC=corp,DC=example,DC=com"),
        (" example.com ", "DC=example,DC=com"),
    ):
        choice = detect_domain(explicit=domain, usernames=(), resolver=resolver)
        assert choice is not None
        client = AdClient(choice.name, "selected-dc")
        assert client.base_dn == expected


def test_go_binary_sid_and_short_input_values():
    value = bytes(
        [
            1,
            5,
            0,
            0,
            0,
            0,
            0,
            5,
            21,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            2,
            0,
            0,
            0,
            3,
            0,
            0,
            0,
            244,
            1,
            0,
            0,
        ]
    )
    assert bytes_to_sid(value) == "S-1-5-21-1-2-3-500"
    # Python represents an unknown/invalid SID as None rather than Go's "".
    assert bytes_to_sid(bytes([1, 5])) is None
