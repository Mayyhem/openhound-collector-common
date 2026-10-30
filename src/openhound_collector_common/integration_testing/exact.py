"""Exact graph records and explicit, narrowly scoped comparison allowances."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..logging import get_logger
from .graph import Edge, Graph, Node

logger = get_logger(__name__)


@dataclass(frozen=True)
class PropertyAllowance:
    """A reviewed exception for one named property on one concrete graph kind.

    `ignore` omits the property; `unordered` compares a list as a multiset. A
    reason is mandatory and copied into reports. Names are literal, not patterns.
    An optional object ID narrows the exception further. No default exceptions
    hide permission, owner, endpoint, credential, evidence, or port changes.
    """

    entity: Literal["node", "edge"]
    kind: str
    property: str
    reason: str
    mode: Literal["ignore", "unordered"] = "ignore"
    object_id: str | None = None

    def __post_init__(self) -> None:
        if self.entity not in ("node", "edge") or self.mode not in ("ignore", "unordered"):
            logger.error("Invalid exact-comparison allowance mode or entity")
            raise ValueError("Allowance entity must be node/edge and mode must be ignore/unordered")
        for value in (self.kind, self.property, self.reason):
            if not isinstance(value, str) or not value.strip():
                logger.error("An exact-comparison allowance is missing its kind, property, or reason")
                raise ValueError("An allowance needs nonempty kind, property, and reason strings")
        if any(character in self.kind + self.property for character in "*?[]"):
            logger.error("Exact-comparison allowances must use literal property/kind names")
            raise ValueError("Allowance kind and property must be literal names, without patterns")
        if self.object_id is not None and (not isinstance(self.object_id, str) or not self.object_id):
            logger.error("An allowance object_id must be a nonempty string")
            raise ValueError("Allowance object_id must be a nonempty string when selected")


@dataclass(frozen=True)
class ExactDifference:
    """One complete record whose count differs, including its original properties."""

    entity: str
    identity: str
    baseline_count: int
    candidate_count: int
    record: dict


def load_allowances(path: str | Path) -> tuple[PropertyAllowance, ...]:
    """Read a JSON list of explicit property exceptions; reject unknown settings."""
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        logger.error("The allowance file must contain a JSON list")
        raise ValueError("The allowance file must contain a JSON list")
    allowed = {"entity", "kind", "property", "reason", "mode", "object_id"}
    result = []
    for item in data:
        if not isinstance(item, dict) or set(item) - allowed:
            logger.error("An allowance contains an unknown field or is not an object")
            raise ValueError("Each allowance must be an object containing only documented fields")
        result.append(PropertyAllowance(**item))
    logger.info("Loaded %d explicit comparison allowance(s)", len(result))
    return tuple(result)


def _properties(
    properties: Mapping,
    *,
    entity: str,
    kinds: Sequence[str],
    object_id: str,
    allowances: Sequence[PropertyAllowance],
) -> dict:
    result = dict(properties)
    for allowance in allowances:
        if allowance.entity != entity or allowance.kind not in kinds or (allowance.object_id is not None and allowance.object_id != object_id):
            # A narrowly scoped exception never changes unrelated records.
            continue
        if allowance.mode == "ignore":
            result.pop(allowance.property, None)
        elif allowance.property in result:
            value = result[allowance.property]
            if not isinstance(value, list):
                logger.error("The unordered allowance for %s.%s found a non-list value", allowance.kind, allowance.property)
                raise ValueError("An unordered allowance can apply only to a list property")
            result[allowance.property] = sorted(value, key=lambda item: json.dumps(item, sort_keys=True))
        # An absent optional property contributes no value to normalize.
    return result


def edge_key(edge: Edge) -> str:
    """Identify endpoints and matching rules without collapsing mapping records."""
    key = f"{edge.start}|{edge.kind}|{edge.end}"
    if edge.start_match_by != "id" or edge.end_match_by != "id":
        # Equal text matched by a name has different meaning from a graph ID.
        return f"{key} [match_by={edge.start_match_by},{edge.end_match_by}]"
    return key


def _node_record(node: Node, allowances: Sequence[PropertyAllowance]) -> dict:
    return {
        "id": node.id,
        # Kinds are graph labels, hence a set. Property lists retain their order.
        "kinds": sorted(node.kinds),
        "properties": _properties(node.properties, entity="node", kinds=node.kinds, object_id=node.id, allowances=allowances),
        "source_kind": node.source_kind,
    }


def _edge_record(edge: Edge, allowances: Sequence[PropertyAllowance]) -> dict:
    return {
        "kind": edge.kind,
        "start": {"value": edge.start, "match_by": edge.start_match_by},
        "end": {"value": edge.end, "match_by": edge.end_match_by},
        "properties": _properties(edge.properties, entity="edge", kinds=[edge.kind], object_id=edge_key(edge), allowances=allowances),
        "source_kind": edge.source_kind,
    }


def exact_differences(baseline: Graph, candidate: Graph, allowances: Sequence[PropertyAllowance] = ()) -> list[ExactDifference]:
    """Compare complete record multisets, preserving raw nodes and every mapping."""
    differences = []
    for entity, baseline_records, candidate_records in (
        ("node", [_node_record(node, allowances) for node in baseline.raw_nodes], [_node_record(node, allowances) for node in candidate.raw_nodes]),
        ("edge", [_edge_record(edge, allowances) for edge in baseline.edges], [_edge_record(edge, allowances) for edge in candidate.edges]),
    ):
        baseline_counts = Counter(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) for record in baseline_records)
        candidate_counts = Counter(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) for record in candidate_records)
        for signature in sorted(set(baseline_counts) | set(candidate_counts)):
            before, after = baseline_counts[signature], candidate_counts[signature]
            if before == after:
                # Matching records need no report entry.
                continue
            record = json.loads(signature)
            identity = record["id"] if entity == "node" else f"{record['start']['value']}|{record['kind']}|{record['end']['value']}"
            differences.append(ExactDifference(entity, identity, before, after, record))
    logger.info("Exact graph comparison found %d differing record(s)", len(differences))
    return differences
