"""The allowed-target list decides which computers may be contacted.

The owner decided on October 30, 2026 that the list accepts names, single IP
addresses and IP ranges; that a listed name is allowed even if it points
outside the listed ranges; and that a computer reached only through a range
must have every address inside it. These checks pin those rules. Nothing here
looks anything up: each test supplies the addresses a collector would pass.
"""

from __future__ import annotations

import pytest

from openhound_collector_common.collection.registry import AllowedTargets

LAB = ["10.10.10.0/24", "10.10.11.0/24"]


def test_no_list_allows_everything():
    decision = AllowedTargets().check(["anything.example.com"], ["203.0.113.5"])
    assert decision.is_allowed
    assert AllowedTargets([" ", ""]).is_empty  # Blank entries add nothing.


@pytest.mark.parametrize(
    ("listed", "candidate", "expected"),
    [
        ("ps1-db.mayyhem.com", "ps1-db.mayyhem.com", True),
        ("ps1-db.mayyhem.com", "PS1-DB.MAYYHEM.COM.", True),  # Case and trailing dot.
        ("ps1-db.mayyhem.com", "ps1-db", True),  # Short name of a listed full name.
        ("ps1-db", "ps1-db.mayyhem.com", True),  # Listed short name.
        ("ps1-db.mayyhem.com", "ps1-db.other.test", False),  # Different full name.
        ("ps1-db.mayyhem.com", "ps1-dbx.mayyhem.com", False),
        ("ps1-db", "ps1-dbx", False),
    ],
)
def test_names_follow_the_short_and_full_name_rule(listed, candidate, expected):
    assert AllowedTargets([listed]).check([candidate], []).is_allowed is expected


def test_listed_name_is_allowed_even_if_it_points_outside_the_ranges():
    # Owner decision: a name typed into the list is explicit permission.
    allowed = AllowedTargets([*LAB, "dmz-sql.mayyhem.com"])
    decision = allowed.check(["dmz-sql.mayyhem.com"], ["172.16.0.5"])
    assert decision.is_allowed
    assert decision.reason == "dmz-sql.mayyhem.com is on the allowed-target list"


def test_every_address_must_be_inside_a_range():
    allowed = AllowedTargets(LAB)
    assert allowed.check(["ps1-db.mayyhem.com"], ["10.10.11.51"]).is_allowed
    split = allowed.check(["both.mayyhem.com"], ["10.10.11.5", "172.16.0.5"])
    assert not split.is_allowed
    assert split.reason == (
        "both.mayyhem.com points to 172.16.0.5, which is not in "
        "10.10.10.0/24 or 10.10.11.0/24"
    )


def test_an_unresolved_name_cannot_be_placed_inside_a_range():
    decision = AllowedTargets(LAB).check(["missing.mayyhem.com"], [])
    assert not decision.is_allowed
    assert "could not be looked up" in decision.reason


def test_a_numeric_name_is_checked_as_an_address():
    allowed = AllowedTargets(
        ["10.10.11.51"]
    )  # A single address is a one-address range.
    assert allowed.check(["10.10.11.51"], []).is_allowed
    refused = allowed.check(["10.10.11.52"], [])
    assert refused.reason == "10.10.11.52, which is not in 10.10.11.51/32"


def test_names_only_list_refuses_unlisted_names_without_needing_addresses():
    decision = AllowedTargets(["ps1-db.mayyhem.com"]).check(["cas-db.mayyhem.com"], [])
    assert decision.reason == "cas-db.mayyhem.com is not on the allowed-target list"


def test_ipv6_ranges_and_zoned_addresses():
    allowed = AllowedTargets(["fd00:10::/64"])
    assert allowed.check(["sql6.mayyhem.com"], ["fd00:10::51%12"]).is_allowed
    assert not allowed.check(["sql6.mayyhem.com"], ["fd00:11::51"]).is_allowed


def test_long_range_lists_are_summarized_in_messages():
    ranges = [f"10.20.{index}.0/24" for index in range(8)]
    decision = AllowedTargets(ranges).check(["far.example"], ["192.0.2.1"])
    assert decision.reason.endswith("or 3 more listed ranges")


def test_mistyped_entries_are_all_reported_before_anything_runs():
    with pytest.raises(ValueError) as caught:
        AllowedTargets(
            [
                "10.10.11.5/24",
                "ps1-db\\SQLEXPRESS",
                "ps1-db:1433",
                "*.mayyhem.com",
                "ok",
            ]
        )
    message = str(caught.value)
    assert "did you mean 10.10.11.0/24?" in message
    for entry in ("ps1-db\\SQLEXPRESS", "ps1-db:1433", "*.mayyhem.com"):
        assert f"'{entry}' is not a computer name" in message
    with pytest.raises(ValueError, match="not a valid IP range"):
        AllowedTargets(["10.10.11.0/33"])


def test_entries_are_kept_in_a_normalized_form_for_saved_settings():
    allowed = AllowedTargets(["PS1-DB.Mayyhem.com.", "10.10.11.51", "10.10.10.0/24"])
    assert allowed.entries == ("ps1-db.mayyhem.com", "10.10.11.51/32", "10.10.10.0/24")
    assert allowed.has_ranges
