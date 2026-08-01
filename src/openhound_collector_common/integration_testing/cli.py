"""Command-line entry point for ``openhound-compare``.

Deliberately argparse, not Typer: this library declares no CLI dependency, and
two positionals plus two flags do not justify imposing one on every collector
that installs it. Kept thin -- parsing and exit code only -- so the comparison
logic stays testable without spawning a subprocess.

``openhound compare`` is not available as a subcommand of the framework binary:
``openhound/main.py`` builds its root Typer app inside ``TyperOverride.__init__``,
which loads extensions through entry points before the app name is bound, so an
extension cannot register a new verb. A console script needs neither.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from openhound_collector_common.integration_testing.compare import compare_graphs
from openhound_collector_common.integration_testing.graph import load_graph


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openhound-compare",
        description="Diff two OpenGraph payloads down to property name and value. "
                    "Each side may be a .zip or a directory of *.json payloads. "
                    "Exits 1 when the candidate lost anything the baseline had; "
                    "additions and ordinary value changes exit 0.",
    )
    p.add_argument("baseline", type=Path,
                   help="The payload that came first -- a saved zip or a convert output directory.")
    p.add_argument("candidate", type=Path,
                   help="The payload being compared against the baseline.")
    p.add_argument("--json", dest="json_path", type=Path, default=None,
                   help="Also write the full report as JSON to this path.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress the console report; the exit code is unaffected.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        baseline = load_graph(args.baseline)
        candidate = load_graph(args.candidate)
    except (ValueError, OSError) as ex:
        # ValueError: load_graph rejects a path that is neither .zip nor a directory.
        # OSError: unreadable path / bad zip. Either way the operator gave us
        # something we cannot diff, which is distinct from finding a regression --
        # hence 2, so a caller can tell "broken invocation" from "found a drop".
        print(f"openhound-compare: {ex}", file=sys.stderr)
        return 2

    report = compare_graphs(baseline, candidate)
    if not args.quiet:
        report.render(log=print)
    if args.json_path is not None:
        args.json_path.write_text(json.dumps(report.to_dict(), indent=2, default=str),
                                  encoding="utf-8")
    return 1 if report.has_regressions else 0
