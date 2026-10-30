"""Write readable, self-contained HTML alongside the existing JSON test report."""

from __future__ import annotations

import json
from collections.abc import Mapping
from html import escape
from pathlib import Path

from openhound_collector_common.integration_testing.results import Summary
from openhound_collector_common.logging import get_logger

logger = get_logger(__name__)


def write_summary_reports(
    summary: Summary,
    json_path: Path,
    *,
    context: Mapping[str, str] | None = None,
) -> Path:
    """Write JSON plus an escaped HTML case table with no external resources.

    Context is caller-owned public information such as profile, input path and
    source version. Never pass credentials or complete collector configuration.
    Report-write failures propagate so callers cannot claim successful reporting.
    """
    document = summary.to_dict()
    document["context"] = dict(context or {})
    json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    html_path = json_path.with_suffix(".html")
    context_rows = "".join(
        f"<dt>{escape(name)}</dt><dd>{escape(value)}</dd>"
        for name, value in (context or {}).items()
    )
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{escape(str(value))}</td>"
            for value in (
                result.case_id,
                result.kind,
                result.description,
                result.outcome,
                result.matched_count,
                result.detail,
            )
        )
        + "</tr>"
        for result in summary.results
    )
    html_path.write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Collector integration results</title>"
        "<style>body{font-family:system-ui;margin:2rem}table{border-collapse:collapse}"
        "th,td{border:1px solid #bbb;padding:.5rem;text-align:left;vertical-align:top}"
        "dt{font-weight:bold}dd{margin-bottom:.5rem}</style>"
        "<h1>Collector integration results</h1>"
        f"<p>Passed: {summary.passed}; failed: {summary.failed}; skipped: {summary.skipped}</p>"
        f"<dl>{context_rows}</dl>"
        "<table><thead><tr><th>Case</th><th>Kind</th><th>Description</th>"
        "<th>Result</th><th>Matches</th><th>Detail</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></html>\n",
        encoding="utf-8",
    )
    logger.info("Integration reports written to %s and %s", json_path, html_path)
    return html_path
