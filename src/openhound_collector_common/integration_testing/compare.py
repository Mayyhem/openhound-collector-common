"""Deep property-level diff between two graphs (the --compare-to-zip engine)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from collections.abc import Sequence
from typing import Callable, Iterable, TypeVar

from openhound_collector_common.integration_testing.graph import Edge, Graph, Node
from .exact import ExactDifference, PropertyAllowance, edge_key, exact_differences

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


# Absence, as distinct from a falsy collected value. 0 and False are real data a
# collector legitimately emits; None/""/[]/{} are what a property looks like when
# the thing that populated it stopped working.
def _is_absent(v) -> bool:
    return v is None or (isinstance(v, (str, list, dict, tuple)) and len(v) == 0)


def _list_items_lost(baseline_v, candidate_v) -> list:
    """Items present in the baseline list and missing from the candidate list.

    Multiset difference over the canonical encoding, so duplicates are counted
    rather than collapsed and ordering is irrelevant -- consistent with
    _values_equal, which already treats lists order-insensitively.
    """
    if not (isinstance(baseline_v, list) and isinstance(candidate_v, list)):
        return []
    remaining = [_canon(i) for i in candidate_v]
    lost = []
    for item in baseline_v:
        c = _canon(item)
        if c in remaining:
            remaining.remove(c)
        else:
            lost.append(item)
    return lost


@dataclass
class Regression:
    """One way the candidate has less than the baseline."""
    category: str      # node-missing | edge-missing | property-missing |
                       # property-emptied | property-shrank | kind-property-missing
    key: str           # node id, "start|kind|end", or the kind name for rollup findings
    kind: str
    detail: str

    def __str__(self) -> str:
        # Kind-level findings carry the kind in BOTH fields (key identifies the
        # finding, kind stays populated so callers can filter on it) -- show it
        # once rather than printing "SCCM_Site SCCM_Site".
        parts = [self.kind, self.key] if self.kind != self.key else [self.key]
        where = " ".join(p for p in parts if p)
        return f"{self.category:<22} {where}  {self.detail}"


@dataclass
class PropDiff:
    key: str          # node id, or "start|kind|end" for edges
    kind: str
    only_in_baseline: dict = field(default_factory=dict)
    only_in_candidate: dict = field(default_factory=dict)
    changed: dict = field(default_factory=dict)   # prop -> {"baseline": v, "candidate": v}


@dataclass
class ComparisonReport:
    nodes_only_in_baseline: list[str] = field(default_factory=list)
    nodes_only_in_candidate: list[str] = field(default_factory=list)
    edges_only_in_baseline: list[str] = field(default_factory=list)
    edges_only_in_candidate: list[str] = field(default_factory=list)
    node_prop_diffs: list[PropDiff] = field(default_factory=list)
    edge_prop_diffs: list[PropDiff] = field(default_factory=list)
    # kind -> {only_in_baseline:[...], only_in_candidate:[...]}
    node_kind_rollup: dict = field(default_factory=dict)
    edge_kind_rollup: dict = field(default_factory=dict)
    exact_requested: bool = False
    exact_record_differences: list[ExactDifference] = field(default_factory=list)
    allowances: tuple[PropertyAllowance, ...] = ()

    @property
    def is_exact_match(self) -> bool | None:
        """Return the requested exact verdict, or None when only losses were checked."""
        return not self.exact_record_differences if self.exact_requested else None

    def to_dict(self) -> dict:
        def pd(d: PropDiff) -> dict:
            return {"key": d.key, "kind": d.kind, "only_in_baseline": d.only_in_baseline,
                    "only_in_candidate": d.only_in_candidate, "changed": d.changed}
        result = {
            "nodes_only_in_baseline": self.nodes_only_in_baseline,
            "nodes_only_in_candidate": self.nodes_only_in_candidate,
            "edges_only_in_baseline": self.edges_only_in_baseline,
            "edges_only_in_candidate": self.edges_only_in_candidate,
            "node_prop_diffs": [pd(d) for d in self.node_prop_diffs],
            "edge_prop_diffs": [pd(d) for d in self.edge_prop_diffs],
            "node_kind_rollup": self.node_kind_rollup, "edge_kind_rollup": self.edge_kind_rollup,
        }
        if self.exact_requested:
            result.update({
                "is_exact_match": self.is_exact_match,
                "exact_record_differences": [asdict(item) for item in self.exact_record_differences],
                "allowances": [asdict(item) for item in self.allowances],
            })
        return result

    def regressions(self) -> list[Regression]:
        """Every way the candidate has less than the baseline.

        Instance-level and kind-level findings both appear: losing the only
        instance carrying a property is reported once per instance AND once for
        the kind, because the two answer different questions ("which node broke?"
        versus "did this property stop being emitted at all?").
        """
        out: list[Regression] = []
        for nid in self.nodes_only_in_baseline:
            out.append(Regression("node-missing", nid, "", "in baseline, absent from candidate"))
        for ekey in self.edges_only_in_baseline:
            out.append(Regression("edge-missing", ekey, "", "in baseline, absent from candidate"))

        for diff in (*self.node_prop_diffs, *self.edge_prop_diffs):
            for prop in sorted(diff.only_in_baseline):
                out.append(Regression("property-missing", diff.key, diff.kind,
                                      f"{prop} no longer emitted"))
            for prop in sorted(diff.changed):
                pair = diff.changed[prop]
                b_val, c_val = pair["baseline"], pair["candidate"]
                if _is_absent(c_val) and not _is_absent(b_val):
                    out.append(Regression("property-emptied", diff.key, diff.kind,
                                          f"{prop}: {b_val!r} -> {c_val!r}"))
                    continue
                lost = _list_items_lost(b_val, c_val)
                if lost:
                    out.append(Regression("property-shrank", diff.key, diff.kind,
                                          f"{prop}: lost {lost!r}"))

        for rollup, what in ((self.node_kind_rollup, "node"), (self.edge_kind_rollup, "edge")):
            for kind in sorted(rollup):
                for prop in rollup[kind]["only_in_baseline"]:
                    out.append(Regression("kind-property-missing", kind, kind,
                                          f"{prop} on no {what} instance in the candidate"))
        return out

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions())

    def _additions(self) -> list[str]:
        """Everything the candidate gained. Never fails a run; always shown."""
        out: list[str] = []
        for nid in self.nodes_only_in_candidate:
            out.append(f"node {nid}")
        for ekey in self.edges_only_in_candidate:
            out.append(f"edge {ekey}")
        for diff in (*self.node_prop_diffs, *self.edge_prop_diffs):
            for prop in sorted(diff.only_in_candidate):
                out.append(f"property {diff.kind} {diff.key}.{prop}")
        for rollup, what in ((self.node_kind_rollup, "node"), (self.edge_kind_rollup, "edge")):
            for kind in sorted(rollup):
                for prop in rollup[kind]["only_in_candidate"]:
                    out.append(f"property {what} kind {kind}.{prop}")
        return out

    def render(self, log: Callable[[str], None] = print) -> None:
        """Print regressions first, then additions, then a one-line verdict.

        Regressions lead because they are the only thing that changes the exit
        code; additions follow so a grown graph is still reviewed rather than
        silently accepted.
        """
        if self.exact_requested:
            log(f"EXACT COMPARISON: {len(self.exact_record_differences)} differing record(s)")
            for difference in self.exact_record_differences:
                log(f"  {difference.entity} {difference.identity}: baseline {difference.baseline_count}, candidate {difference.candidate_count}")
            for allowance in self.allowances:
                log(f"  Allowance: {allowance.entity} {allowance.kind}.{allowance.property} ({allowance.mode}): {allowance.reason}")
            log("RESULT: exact match" if self.is_exact_match else "RESULT: graphs differ")
            return
        regs = self.regressions()
        bar = "=" * 72
        log(bar)
        log(f"REGRESSIONS ({len(regs)}) -- present in baseline, missing or reduced in candidate")
        log(bar)
        if regs:
            for r in regs:
                log(f"  - {r}")
        else:
            log("  (none)")

        adds = self._additions()
        log(bar)
        log(f"ADDED ({len(adds)}) -- in candidate only; review, but does not fail the run")
        log(bar)
        if adds:
            for a in adds:
                log(f"  + {a}")
        else:
            log("  (none)")

        # Changed values that are neither a loss nor an addition: reported for
        # context only, and deliberately not counted in either headline number.
        changed = sum(len(d.changed) for d in (*self.node_prop_diffs, *self.edge_prop_diffs))
        log(bar)
        log(f"RESULT: {len(regs)} regressions, {len(adds)} additions, {changed} changed values.")


def _diff_props(key: str, kind: str, baseline_props: dict, candidate_props: dict) -> PropDiff | None:
    d = PropDiff(key=key, kind=kind)
    for k, v in baseline_props.items():
        if k not in candidate_props:
            d.only_in_baseline[k] = v
        elif not _values_equal(v, candidate_props[k]):
            d.changed[k] = {"baseline": v, "candidate": candidate_props[k]}
    for k, v in candidate_props.items():
        if k not in baseline_props:
            d.only_in_candidate[k] = v
    return d if (d.only_in_baseline or d.only_in_candidate or d.changed) else None


def _kind_rollup(baseline_items: Iterable[_Item], candidate_items: Iterable[_Item],
                 kinds_of: Callable[[_Item], list[str]]) -> dict:
    """Union of property names seen per kind, separately for each side.

    Plain accumulation loops (not comprehensions) so each side's dict is
    unambiguous: no risk of a shared/rebound variable silently pointing both
    loops at the same accumulator.
    """
    baseline_props: dict[str, set] = {}
    for item in baseline_items:
        for kind in kinds_of(item):
            baseline_props.setdefault(kind, set()).update(item.properties.keys())
    candidate_props: dict[str, set] = {}
    for item in candidate_items:
        for kind in kinds_of(item):
            candidate_props.setdefault(kind, set()).update(item.properties.keys())
    roll = {}
    for kind in set(baseline_props) | set(candidate_props):
        pb, pc = baseline_props.get(kind, set()), candidate_props.get(kind, set())
        roll[kind] = {"only_in_baseline": sorted(pb - pc), "only_in_candidate": sorted(pc - pb)}
    return roll


def compare_graphs(baseline: Graph, candidate: Graph, *, exact: bool = False, allowances: Sequence[PropertyAllowance] = ()) -> ComparisonReport:
    """Diff *candidate* against *baseline*. Baseline is what came first.

    Membership and property differences are reported in both directions; only the
    baseline-has/candidate-lacks direction counts as a regression (see regressions()).
    """
    rep = ComparisonReport(exact_requested=exact, allowances=tuple(allowances))
    if exact:
        rep.exact_record_differences = exact_differences(baseline, candidate, allowances)
    b_nodes = {n.id: n for n in baseline.nodes}
    c_nodes = {n.id: n for n in candidate.nodes}
    rep.nodes_only_in_baseline = sorted(set(b_nodes) - set(c_nodes))
    rep.nodes_only_in_candidate = sorted(set(c_nodes) - set(b_nodes))
    for nid in sorted(set(b_nodes) & set(c_nodes)):
        nb, nc = b_nodes[nid], c_nodes[nid]
        d = _diff_props(nid, nb.kinds[0] if nb.kinds else "?", nb.properties, nc.properties)
        if d:
            rep.node_prop_diffs.append(d)

    # A dictionary containing one edge per endpoint triple silently lost
    # additional login mappings. Keep every record, cancel unchanged pairs, then
    # compare the remaining records in a deterministic order.
    b_edges: dict[str, list[Edge]] = {}
    c_edges: dict[str, list[Edge]] = {}
    for edge in baseline.edges:
        b_edges.setdefault(edge_key(edge), []).append(edge)
    for edge in candidate.edges:
        c_edges.setdefault(edge_key(edge), []).append(edge)
    for key in sorted(set(b_edges) | set(c_edges)):
        before = sorted(b_edges.get(key, []), key=lambda edge: _canon(edge.properties))
        after = sorted(c_edges.get(key, []), key=lambda edge: _canon(edge.properties))
        remaining = []
        for edge in before:
            match = next((index for index, other in enumerate(after) if not _diff_props(key, edge.kind, edge.properties, other.properties)), None)
            if match is None:
                remaining.append(edge)
            else:
                # One occurrence cancels one occurrence, preserving multiplicity.
                after.pop(match)
        paired = min(len(remaining), len(after))
        for index in range(paired):
            difference = _diff_props(key, remaining[index].kind, remaining[index].properties, after[index].properties)
            if difference:
                rep.edge_prop_diffs.append(difference)
        rep.edges_only_in_baseline.extend([key] * (len(remaining) - paired))
        rep.edges_only_in_candidate.extend([key] * (len(after) - paired))

    rep.node_kind_rollup = _kind_rollup(baseline.nodes, candidate.nodes, lambda n: n.kinds)
    rep.edge_kind_rollup = _kind_rollup(baseline.edges, candidate.edges, lambda e: [e.kind])
    return rep
