"""Check graph files before duplicate records can be merged by the loader."""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class RawIssue:
    """One invalid record with its file and plain-English explanation."""

    filename: str
    detail: str


class GraphValidationError(ValueError):
    """The selected files do not contain a trustworthy raw graph."""

    def __init__(self, issues: list[RawIssue]):
        self.issues = issues
        super().__init__("; ".join(f"{issue.filename}: {issue.detail}" for issue in issues))


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject repeated JSON keys instead of silently retaining the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            logger.error("Graph JSON repeats key %r", key)
            raise ValueError(f"JSON repeats key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    """JSON graph numbers cannot be NaN or infinity."""
    logger.error("Graph JSON contains a non-finite number: %s", value)
    raise ValueError(f"Graph JSON contains a non-finite number: {value}")


def parse_checked_payloads(files: list[tuple[str, str]]) -> list[tuple[str, dict]]:
    """Validate raw shape, duplicate nodes, and identical repeated relationships.

    Complementary properties on a repeated node ID are allowed; contradicting
    shared properties are errors. Relationships with different properties remain
    separate records, allowing distinct login mappings between equal endpoints.
    This function deliberately runs before Graph's existing node merge.
    """
    issues: list[RawIssue] = []
    payloads = []
    nodes_by_id: dict[str, tuple[str, dict]] = {}
    edges_seen: dict[str, str] = {}
    if not files:
        logger.error("No graph JSON files were selected")
        raise GraphValidationError([RawIssue("<input>", "no graph JSON files found")])
    for filename, text in files:
        try:
            payload = json.loads(text, object_pairs_hook=_unique_keys, parse_constant=_reject_nonfinite)
            if not isinstance(payload, dict) or not isinstance(payload.get("graph"), dict):
                raise ValueError("expected an object containing a graph object")
            graph = payload["graph"]
            if "nodes" not in graph and "edges" not in graph:
                raise ValueError("graph must contain nodes or edges, including an explicitly empty list")
            for collection in ("nodes", "edges"):
                if collection in graph and not isinstance(graph[collection], list):
                    raise ValueError(f"graph.{collection} must be a list")
            metadata = payload.get("metadata", {})
            if not isinstance(metadata, dict):
                raise ValueError("metadata must be an object")
            source_kind = metadata.get("source_kind")
            if source_kind is not None and not isinstance(source_kind, str):
                raise ValueError("metadata.source_kind must be a string when present")
        except (ValueError, TypeError) as error:
            logger.error("Invalid graph payload %s: %s", filename, error)
            issues.append(RawIssue(filename, str(error)))
            continue

        for index, node in enumerate(graph.get("nodes", [])):
            try:
                if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
                    raise ValueError(f"node {index} needs a nonempty string ID")
                kinds = node.get("kinds")
                if not isinstance(kinds, list) or not kinds or not all(isinstance(kind, str) and kind for kind in kinds):
                    raise ValueError(f"node {node['id']} needs a nonempty list of kind strings")
                if len(kinds) != len(set(kinds)):
                    raise ValueError(f"node {node['id']} repeats a kind")
                properties = node.get("properties", {})
                if not isinstance(properties, dict):
                    raise ValueError(f"node {node['id']} properties must be an object")
                previous = nodes_by_id.get(node["id"])
                if previous:
                    previous_file, known = previous
                    for key in set(known) & set(properties):
                        if json.dumps(known[key], sort_keys=True) != json.dumps(properties[key], sort_keys=True):
                            raise ValueError(f"node {node['id']} contradicts property {key!r} in {previous_file}")
                    known.update(properties)
                    logger.debug("Complementary/identical node %s also appears in %s", node["id"], filename)
                else:
                    nodes_by_id[node["id"]] = (filename, dict(properties))
            except ValueError as error:
                logger.error("Invalid raw node in %s: %s", filename, error)
                issues.append(RawIssue(filename, str(error)))

        for index, edge in enumerate(graph.get("edges", [])):
            try:
                if not isinstance(edge, dict) or not isinstance(edge.get("kind"), str) or not edge["kind"]:
                    raise ValueError(f"relationship {index} needs a nonempty kind string")
                for end in ("start", "end"):
                    endpoint = edge.get(end)
                    if not isinstance(endpoint, dict) or not isinstance(endpoint.get("value"), str) or not endpoint["value"]:
                        raise ValueError(f"relationship {index} needs a nonempty {end}.value string")
                    if not isinstance(endpoint.get("match_by", "id"), str):
                        raise ValueError(f"relationship {index} {end}.match_by must be a string")
                if not isinstance(edge.get("properties", {}), dict):
                    raise ValueError(f"relationship {index} properties must be an object")
                signature = json.dumps(edge, sort_keys=True, separators=(",", ":"))
                if signature in edges_seen:
                    raise ValueError(f"relationship {index} duplicates an identical record in {edges_seen[signature]}")
                edges_seen[signature] = filename
            except ValueError as error:
                logger.error("Invalid raw relationship in %s: %s", filename, error)
                issues.append(RawIssue(filename, str(error)))
        payloads.append((filename, payload))
    if issues:
        logger.error("Raw graph validation found %d issue(s)", len(issues))
        raise GraphValidationError(issues)
    logger.info("Raw graph validation passed for %d payload file(s)", len(payloads))
    return payloads
