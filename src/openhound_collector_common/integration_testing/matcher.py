"""Wildcard/pattern matching — port of the PowerShell kit's Test-*Pattern helpers."""

from __future__ import annotations

import fnmatch
import re

from openhound_collector_common.integration_testing.cases import EdgeCase, NodePattern
from openhound_collector_common.integration_testing.graph import Edge, Graph, Node


def endpoint_id_match(
    actual: str, pattern: str, *, match_name_before_at: bool = False
) -> bool:
    """Match reference IDs with only * and ? wildcards, ignoring letter case.

    Square brackets are ordinary characters. The optional name rule compares
    only the portion before @ for patterns without wildcards, matching tools
    that leave the collected server suffix unspecified in their fixtures.
    """
    if "*" in pattern or "?" in pattern:
        # Escape everything first so brackets and other punctuation stay literal.
        expression = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        return (
            re.fullmatch(expression, actual, flags=re.IGNORECASE | re.DOTALL)
            is not None
        )
    if match_name_before_at and "@" in pattern:
        return actual.split("@", 1)[0].casefold() == pattern.split("@", 1)[0].casefold()
    # Exact matching is the ordinary case and needs no per-edge diagnostic.
    return actual.casefold() == pattern.casefold()


def exact_value_match(actual: object, expected: object) -> bool:
    """Compare JSON values without accepting changed types, case, or list order."""
    # These are pure assertion predicates; the runner reports any failed case.
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(
            exact_value_match(a, e) for a, e in zip(actual, expected)
        )
    if isinstance(actual, dict) and isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            exact_value_match(actual[key], expected[key]) for key in actual
        )
    return actual == expected


def property_match(actual, expected, *, exact: bool = False) -> bool:
    """Match one property value. Ports Test-PropertyMatch."""
    if exact:
        return exact_value_match(actual, expected)
    # Existing collectors retain their pattern/subset matching rules by default.
    if actual is None and expected is None:
        return True
    if actual is None or expected is None:
        return False
    # Lists: every expected item must match some actual item (subset).
    if isinstance(expected, list) and isinstance(actual, list):
        return all(any(property_match(a, e) for a in actual) for e in expected)
    if isinstance(expected, list) or isinstance(actual, list):
        return False
    # Booleans: coerce the actual side ("True"/"1"/"False"/"0").
    if isinstance(expected, bool):
        if isinstance(actual, bool):
            return actual == expected
        s = str(actual).strip().lower()
        if s in ("true", "1"):
            return expected is True
        if s in ("false", "0"):
            return expected is False
        return False
    actual_s, expected_s = str(actual), str(expected)
    if "*" in expected_s or "?" in expected_s:
        return fnmatch.fnmatch(actual_s.lower(), expected_s.lower())
    return actual_s.lower() == expected_s.lower()


def _node_prop(node: Node, key: str):
    """Property lookup: node.properties[key], falling back to node.id / node.kinds."""
    if key in node.properties:
        return node.properties[key]
    if key == "id":
        return node.id
    if key == "kinds":
        return node.kinds
    return None


def node_matches(node: Node, pattern: NodePattern) -> bool:
    """Ports Test-NodePattern: kind subset (Base always satisfied) + property match."""
    if pattern.kinds:
        for k in pattern.kinds:
            if k == "Base":
                continue
            if k not in node.kinds:
                return False
    if pattern.properties:
        for key, expected in pattern.properties.items():
            if not property_match(_node_prop(node, key), expected):
                return False
    return True


def edge_matches(edge: Edge, graph: Graph, case: EdgeCase) -> bool:
    """Ports Test-EdgePattern: exact kind + endpoint nodes + edge properties."""
    if edge.kind != case.kind:
        return False
    if case.source_id_pattern is not None or case.target_id_pattern is not None:
        # ID assertions do not depend on a node being present in the reference
        # output. Additional node filters, when supplied, still require it.
        for actual, pattern, node_pattern in (
            (edge.start, case.source_id_pattern, case.source),
            (edge.end, case.target_id_pattern, case.target),
        ):
            if pattern is not None and not endpoint_id_match(
                actual, pattern, match_name_before_at=case.match_name_before_at
            ):
                return False
            if node_pattern is not None:
                node = graph.node(actual)
                if node is None or not node_matches(node, node_pattern):
                    return False
            # No node filter means the endpoint's ID is sufficient.
        return not case.properties or all(
            key in edge.properties
            and property_match(
                edge.properties[key], expected, exact=case.exact_property_values
            )
            for key, expected in case.properties.items()
        )
    # Existing consumers continue to require both endpoint nodes.
    src, tgt = graph.node(edge.start), graph.node(edge.end)
    if src is None or tgt is None:
        return False
    if case.source and not node_matches(src, case.source):
        return False
    if case.target and not node_matches(tgt, case.target):
        return False
    if case.properties:
        for key, expected in case.properties.items():
            if not property_match(
                edge.properties.get(key), expected, exact=case.exact_property_values
            ):
                return False
    return True
