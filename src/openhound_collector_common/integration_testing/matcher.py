"""Wildcard/pattern matching — port of the PowerShell kit's Test-*Pattern helpers."""
from __future__ import annotations

import fnmatch

from openhound_collector_common.integration_testing.cases import EdgeCase, NodePattern
from openhound_collector_common.integration_testing.graph import Edge, Graph, Node


def property_match(actual, expected) -> bool:
    """Match one property value. Ports Test-PropertyMatch."""
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
    src, tgt = graph.node(edge.start), graph.node(edge.end)
    if src is None or tgt is None:
        return False
    if case.source and not node_matches(src, case.source):
        return False
    if case.target and not node_matches(tgt, case.target):
        return False
    if case.properties:
        for key, expected in case.properties.items():
            if not property_match(edge.properties.get(key), expected):
                return False
    return True
