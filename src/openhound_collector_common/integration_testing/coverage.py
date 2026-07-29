"""Coverage: which schema.json kinds have no fixture test (replaces the dead Get-MissingTests)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase


def load_schema_kinds(schema_path) -> tuple[set[str], set[str]]:
    doc = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    node_kinds = {k["name"] for k in doc.get("node_kinds", [])}
    edge_kinds = {k["name"] for k in doc.get("relationship_kinds", [])}
    return node_kinds, edge_kinds


def coverage(schema_path, edge_cases: list[EdgeCase], node_cases: list[NodeCase]) -> dict:
    node_kinds, edge_kinds = load_schema_kinds(schema_path)
    covered_edge = {c.kind for c in edge_cases}
    covered_node = {k for c in node_cases for k in c.kinds}
    return {"untested_edge_kinds": sorted(edge_kinds - covered_edge),
            "untested_node_kinds": sorted(node_kinds - covered_node)}


def report(schema_path, edge_cases, node_cases, log: Callable[[str], None] = print) -> dict:
    cov = coverage(schema_path, edge_cases, node_cases)
    log("\nCoverage (schema kinds without a fixture test):")
    log(f"  Untested edge kinds: {cov['untested_edge_kinds'] or 'none'}")
    log(f"  Untested node kinds: {cov['untested_node_kinds'] or 'none'}")
    return cov
