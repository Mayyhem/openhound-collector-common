"""Deep property-level diff between two graphs (the --compare-to-zip engine)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Iterable, TypeVar

from openhound_collector_common.integration_testing.graph import Edge, Graph, Node

# _kind_rollup is called once for nodes and once for edges. A `Node | Edge` parameter would
# force each caller's lambda to handle both, so the accessor could not simply reach for
# `.kinds` or `.kind`; a type variable ties the items and their accessor together instead.
# Constrained to the two concrete types rather than left open, because the body reads
# `.properties` -- which both have, and an unconstrained variable would not guarantee.
_Item = TypeVar("_Item", Node, Edge)


def _canon(v):
    return json.dumps(v, sort_keys=True, default=str)


def _values_equal(x, y) -> bool:
    """Scalars: exact. Lists: order-insensitive (multiset) so ordering isn't noise."""
    if isinstance(x, list) and isinstance(y, list):
        return sorted(_canon(i) for i in x) == sorted(_canon(i) for i in y)
    if isinstance(x, list) or isinstance(y, list):
        return False
    return x == y


@dataclass
class PropDiff:
    key: str          # node id, or "start|kind|end" for edges
    kind: str
    only_in_a: dict = field(default_factory=dict)
    only_in_b: dict = field(default_factory=dict)
    changed: dict = field(default_factory=dict)   # prop -> [a_val, b_val]


@dataclass
class ComparisonReport:
    nodes_only_in_a: list[str] = field(default_factory=list)
    nodes_only_in_b: list[str] = field(default_factory=list)
    edges_only_in_a: list[str] = field(default_factory=list)
    edges_only_in_b: list[str] = field(default_factory=list)
    node_prop_diffs: list[PropDiff] = field(default_factory=list)
    edge_prop_diffs: list[PropDiff] = field(default_factory=list)
    node_kind_rollup: dict = field(default_factory=dict)   # kind -> {only_a:[...], only_b:[...]}
    edge_kind_rollup: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        def pd(d: PropDiff) -> dict:
            return {"key": d.key, "kind": d.kind, "only_in_a": d.only_in_a,
                    "only_in_b": d.only_in_b, "changed": d.changed}
        return {
            "nodes_only_in_a": self.nodes_only_in_a, "nodes_only_in_b": self.nodes_only_in_b,
            "edges_only_in_a": self.edges_only_in_a, "edges_only_in_b": self.edges_only_in_b,
            "node_prop_diffs": [pd(d) for d in self.node_prop_diffs],
            "edge_prop_diffs": [pd(d) for d in self.edge_prop_diffs],
            "node_kind_rollup": self.node_kind_rollup, "edge_kind_rollup": self.edge_kind_rollup,
        }

    def render(self, log: Callable[[str], None] = print) -> None:
        log(f"Nodes only in A (current run): {len(self.nodes_only_in_a)}")
        for nid in self.nodes_only_in_a:
            log(f"  + {nid}")
        log(f"Nodes only in B (compare zip): {len(self.nodes_only_in_b)}")
        for nid in self.nodes_only_in_b:
            log(f"  - {nid}")
        log(f"Edges only in A: {len(self.edges_only_in_a)}   only in B: {len(self.edges_only_in_b)}")
        for d in self.node_prop_diffs:
            log(f"Node {d.key} [{d.kind}]: onlyA={list(d.only_in_a)} onlyB={list(d.only_in_b)} changed={d.changed}")
        for d in self.edge_prop_diffs:
            log(f"Edge {d.key}: onlyA={list(d.only_in_a)} onlyB={list(d.only_in_b)} changed={d.changed}")
        log("By-kind property rollup (node kinds):")
        for kind, roll in sorted(self.node_kind_rollup.items()):
            if roll["only_a"] or roll["only_b"]:
                log(f"  {kind}: only_in_A={roll['only_a']} only_in_B={roll['only_b']}")
        log("By-kind property rollup (edge kinds):")
        for kind, roll in sorted(self.edge_kind_rollup.items()):
            if roll["only_a"] or roll["only_b"]:
                log(f"  {kind}: only_in_A={roll['only_a']} only_in_B={roll['only_b']}")


def _diff_props(key: str, kind: str, a_props: dict, b_props: dict) -> PropDiff | None:
    d = PropDiff(key=key, kind=kind)
    for k, v in a_props.items():
        if k not in b_props:
            d.only_in_a[k] = v
        elif not _values_equal(v, b_props[k]):
            d.changed[k] = [v, b_props[k]]
    for k, v in b_props.items():
        if k not in a_props:
            d.only_in_b[k] = v
    return d if (d.only_in_a or d.only_in_b or d.changed) else None


def _kind_rollup(a_items: Iterable[_Item], b_items: Iterable[_Item],
                 kinds_of: Callable[[_Item], list[str]]) -> dict:
    """Union of property names seen per kind, separately for side A and side B.

    Plain accumulation loop (not a comprehension) so each side's dict is
    unambiguous: no risk of a shared/rebound `side` variable silently pointing
    both loops at the same accumulator.
    """
    a_props: dict[str, set] = {}
    for item in a_items:
        for kind in kinds_of(item):
            a_props.setdefault(kind, set()).update(item.properties.keys())
    b_props: dict[str, set] = {}
    for item in b_items:
        for kind in kinds_of(item):
            b_props.setdefault(kind, set()).update(item.properties.keys())
    roll = {}
    for kind in set(a_props) | set(b_props):
        pa, pb = a_props.get(kind, set()), b_props.get(kind, set())
        roll[kind] = {"only_a": sorted(pa - pb), "only_b": sorted(pb - pa)}
    return roll


def compare_graphs(a: Graph, b: Graph) -> ComparisonReport:
    rep = ComparisonReport()
    a_nodes = {n.id: n for n in a.nodes}
    b_nodes = {n.id: n for n in b.nodes}
    rep.nodes_only_in_a = sorted(set(a_nodes) - set(b_nodes))
    rep.nodes_only_in_b = sorted(set(b_nodes) - set(a_nodes))
    for nid in sorted(set(a_nodes) & set(b_nodes)):
        na, nb = a_nodes[nid], b_nodes[nid]
        d = _diff_props(nid, na.kinds[0] if na.kinds else "?", na.properties, nb.properties)
        if d:
            rep.node_prop_diffs.append(d)

    def ekey(e: Edge) -> str:
        return f"{e.start}|{e.kind}|{e.end}"

    a_edges = {ekey(e): e for e in a.edges}
    b_edges = {ekey(e): e for e in b.edges}
    rep.edges_only_in_a = sorted(set(a_edges) - set(b_edges))
    rep.edges_only_in_b = sorted(set(b_edges) - set(a_edges))
    for k in sorted(set(a_edges) & set(b_edges)):
        ea, eb = a_edges[k], b_edges[k]
        d = _diff_props(k, ea.kind, ea.properties, eb.properties)
        if d:
            rep.edge_prop_diffs.append(d)

    rep.node_kind_rollup = _kind_rollup(a.nodes, b.nodes, lambda n: n.kinds)
    rep.edge_kind_rollup = _kind_rollup(a.edges, b.edges, lambda e: [e.kind])
    return rep
