"""Runs edge/node cases + invariants against a Graph; prints + returns a Summary."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing import coverage as _coverage
from openhound_collector_common.integration_testing.cases import CountSpec, EdgeCase, NodeCase, NodePattern
from openhound_collector_common.integration_testing.graph import Graph
from openhound_collector_common.integration_testing.matcher import edge_matches, node_matches
from openhound_collector_common.integration_testing.results import (
    FAIL, PASS, SKIP, Result, Summary, write_results_json)

Invariant = Callable[[Graph], Result]


def _count_ok(spec: CountSpec | None, n: int) -> bool:
    return n >= 1 if spec is None else spec.satisfied_by(n)


def run_edge_case(case: EdgeCase, graph: Graph) -> Result:
    if not case.source and not case.target and not case.properties:
        return Result(case.id, case.kind, case.description, SKIP, "coverage placeholder")
    matches = [e for e in graph.edges_of_kind(case.kind) if edge_matches(e, graph, case)]
    n = len(matches)
    if case.negative:
        return (Result(case.id, case.kind, case.description, PASS, "correctly absent") if n == 0
                else Result(case.id, case.kind, case.description, FAIL, f"incorrectly present ({n})", n))
    if n == 0:
        return Result(case.id, case.kind, case.description, FAIL, "not found", 0)
    if not _count_ok(case.count, n):
        return Result(case.id, case.kind, case.description, FAIL, f"wrong count (found {n})", n)
    return Result(case.id, case.kind, case.description, PASS, "", n)


def run_node_case(case: NodeCase, graph: Graph) -> Result:
    pattern = NodePattern(kinds=case.kinds, properties=case.properties)
    matches = [nd for nd in graph.nodes if node_matches(nd, pattern)]
    n = len(matches)
    label = case.kinds[0] if case.kinds else "node"
    if case.negative:
        return (Result(case.id, label, case.description, PASS, "correctly absent") if n == 0
                else Result(case.id, label, case.description, FAIL, f"incorrectly present ({n})", n))
    if n == 0:
        return Result(case.id, label, case.description, FAIL, "not found", 0)
    if not _count_ok(case.count, n):
        return Result(case.id, label, case.description, FAIL, f"wrong count (found {n})", n)
    return Result(case.id, label, case.description, PASS, "", n)


def _line(r: Result) -> str:
    return f"{r.kind}: {r.description} - {r.outcome}" + (f" ({r.detail})" if r.detail else "")


def run_suite(graph: Graph, edge_cases: list[EdgeCase], node_cases: list[NodeCase],
              invariants: list[Invariant] | None = None, schema_path: Path | None = None,
              results_path: Path | None = None, log: Callable[[str], None] = print) -> Summary:
    summary = Summary()
    log(f"Total nodes found: {len(graph.nodes)}")
    log(f"Total edges found: {len(graph.edges)}")
    log("Edge types found:")
    for kind, count in sorted(Counter(e.kind for e in graph.edges).items()):
        log(f"  {kind}: {count}")

    log("\nRunning edge tests...")
    for case in edge_cases:
        r = run_edge_case(case, graph)
        summary.results.append(r)
        log(_line(r))
    log("\nRunning node tests...")
    for ncase in node_cases:
        r = run_node_case(ncase, graph)
        summary.results.append(r)
        log(_line(r))
    for inv in invariants or []:
        # An invariant is arbitrary caller code; a bug in one must not crash the whole
        # run (the suite never raises on a failing check) — turn an exception into a FAIL.
        name = getattr(inv, "__name__", "invariant")
        try:
            r = inv(graph)
        except Exception as exc:  # noqa: BLE001 - surface any invariant crash as a FAIL result
            r = Result(name, "invariant", f"{name} raised an exception", FAIL, str(exc)[:120])
        summary.results.append(r)
        log(_line(r))

    log("\nEdge Test Summary:")
    log(f"  Passed: {summary.passed}")
    log(f"  Failed: {summary.failed}")
    log(f"  Skipped: {summary.skipped}")

    if schema_path is not None:
        _coverage.report(schema_path, edge_cases, node_cases, log=log)
    if results_path is not None:
        write_results_json(summary, results_path)
    return summary
