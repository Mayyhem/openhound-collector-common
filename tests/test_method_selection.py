"""The parser supplies mechanics; collector boundaries own valid names and dependencies."""

import pytest

from openhound_collector_common.collection.methods import parse_methods
from openhound_collector_common.orchestration.arguments import (
    suspicious_argument_warnings,
)


@pytest.mark.parametrize(
    "value,name,expected",
    [
        (None, "LDAP", True),
        ("", "anything", True),
        ("All", "anything", True),
        ("LDAP, Wmi,ldap", "LDAP", True),
        ("LDAP, Wmi,ldap", "wmi", True),
        ("LDAP, Wmi,ldap", "MSSQL", False),
        ("unknown", "LDAP", False),
        (" ", "LDAP", False),
    ],
)
def test_shared_selection_preserves_case_deduplication_and_all(value, name, expected):
    assert parse_methods(value).includes(name) is expected


def test_argument_vocabulary_and_sensitive_value_rules_belong_to_the_caller():
    warnings = suspicious_argument_warnings(
        ["-dc", "10.10.10.100", "-pMy", "Secret", "-uNa", "user:password@host"],
        short_options={"-d": "--domain", "-p": "--password", "-u": "--user"},
        long_options={"--dc"},
        sensitive_options={"-p"},
        is_sensitive_value=lambda value: "@" in value,
    )
    assert len(warnings) == 3
    assert "--dc 10.10.10.100" in warnings[0]
    assert all(
        secret not in "\n".join(warnings)
        for secret in ("Secret", "My", "user:password", "Na")
    )
    assert (
        suspicious_argument_warnings(
            ["--dc", "10.10.10.100"],
            short_options={},
            long_options={"--dc"},
            sensitive_options=set(),
        )
        == []
    )
