"""Reference assertions must not overlook wrong properties or absent native nodes."""

import pytest

from openhound_collector_common.integration_testing.cases import CountSpec, EdgeCase
from openhound_collector_common.integration_testing.graph import Edge, Graph
from openhound_collector_common.integration_testing.matcher import endpoint_id_match
from openhound_collector_common.integration_testing.runner import run_edge_case


@pytest.mark.parametrize(
    "actual,pattern,name_rule,expected",
    [
        ("Login@server-a", "login@server-b", True, True),
        ("Login@server-a", "login@server-b", False, False),
        ("Login@server-a", "login@*", True, True),
        ("login@server-a", "login@server-?", False, True),
        ("login@server-aa", "login@server-?", False, False),
        ("login[1]@server", "login[1]@*", False, True),
        ("login1@server", "login[1]@*", False, False),
        ("native-SID", "NATIVE-sid", True, True),
    ],
)
def test_reference_endpoint_matching(actual, pattern, name_rule, expected):
    assert (
        endpoint_id_match(actual, pattern, match_name_before_at=name_rule) is expected
    )


def case(**changes):
    values = dict(
        id="required",
        kind="relationship",
        description="Reference assertion",
        source_id_pattern="login@*",
        target_id_pattern="server",
        properties_must_match_all=True,
    )
    return EdgeCase(**(values | changes))


def test_endpoint_assertion_does_not_require_native_node_definitions():
    graph = Graph([], [Edge("relationship", "login@server", "server")])
    assert run_edge_case(case(), graph).outcome == "PASS"


def test_wrong_property_cannot_hide_behind_another_correct_edge():
    graph = Graph(
        [],
        [
            Edge("relationship", "login@server", "server", {"traversable": value})
            for value in (True, False)
        ],
    )
    result = run_edge_case(case(properties={"traversable": True}), graph)
    assert result.outcome == "FAIL"
    assert result.matched_count == 2
    assert "property mismatch" in result.detail


@pytest.mark.parametrize(
    "number,negative,count,expected",
    [
        (0, True, None, "PASS"),
        (1, True, None, "FAIL"),
        (0, False, None, "FAIL"),
        (1, False, None, "PASS"),
        (2, False, CountSpec(exact=1), "FAIL"),
        (2, False, CountSpec(at_least=1), "PASS"),
    ],
)
def test_required_forbidden_and_explicit_extra_counts(
    number, negative, count, expected
):
    graph = Graph(
        [], [Edge("relationship", "login@server", "server") for _ in range(number)]
    )
    assert (
        run_edge_case(case(negative=negative, count=count), graph).outcome == expected
    )
