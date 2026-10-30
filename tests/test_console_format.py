"""Match actual Go transcripts and keep opt-in formatting independent of defaults."""

from __future__ import annotations

import io
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from openhound_collector_common.logging import (
    VERBOSE,
    GoConsoleFormatter,
    LogContextFilter,
    SecretRedactor,
    console_supports_color,
    log_event,
    phase_context,
    target_context,
)

GOLDEN = json.loads((Path(__file__).parent / "fixtures/go_console.json").read_text())


@pytest.mark.parametrize(
    "sample",
    GOLDEN["samples"],
    ids=[sample["level"] + sample["message"] for sample in GOLDEN["samples"]],
)
@pytest.mark.parametrize("color", [False, True])
def test_fixed_records_match_pinned_go_output(sample, color):
    level = (
        VERBOSE
        if sample["level"] == "VERBOSE"
        else logging.getLevelName(sample["level"])
    )
    record = logging.LogRecord("test", level, "", 0, sample["message"], (), None)
    record.created = GOLDEN["created"]
    record._oh_target = sample["target"]
    record._oh_fields = [(field["key"], field["value"]) for field in sample["fields"]]
    expected = sample["color" if color else "plain"]
    assert GoConsoleFormatter(color=color).format(record) + "\n" == expected


def test_existing_context_prefix_does_not_duplicate_target_or_change_old_output():
    record = logging.LogRecord(
        "test", logging.INFO, "", 0, "Collected %d records", (2,), None
    )
    with target_context("lab-a"), phase_context("collect"):
        LogContextFilter().filter(record)
        assert record.getMessage() == "[lab-a][collect] Collected 2 records"
        formatted = GoConsoleFormatter().format(record)
    assert formatted.count("[lab-a]") == 1
    assert formatted.endswith("[lab-a] Collected 2 records phase=collect")
    assert record.getMessage() == "[lab-a][collect] Collected 2 records"


def test_known_secrets_inline_credentials_and_secret_fields_are_redacted():
    record = logging.LogRecord(
        "test",
        logging.DEBUG,
        "",
        0,
        "server user:example-password@host supplied known-ticket",
        (),
        None,
    )
    record._oh_fields = [
        ("password", "unregistered-password"),
        ("nt_hash", "other-hash"),
        ("error", "cannot use known-ticket"),
        ("count", 0),
        ("enabled", False),
    ]
    text = GoConsoleFormatter(secrets=["known-ticket"]).format(record)
    for secret in (
        "example-password",
        "known-ticket",
        "unregistered-password",
        "other-hash",
    ):
        assert secret not in text
    assert "count=0 enabled=false" in text
    assert "user:<redacted>@host" in text


def test_redactor_does_not_print_or_expose_its_supplied_values():
    redactor = SecretRedactor(["long-secret", "secret"])
    assert redactor.redact("long-secret secret") == "<redacted> <redacted>"
    assert "long-secret" not in repr(redactor)


def test_redirected_and_explicit_plain_streams_do_not_enable_color():
    assert console_supports_color(io.StringIO()) is False
    assert console_supports_color(io.StringIO(), no_color=True) is False


def test_concurrent_targets_write_complete_lines_with_their_own_context():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(GoConsoleFormatter())
    logger = logging.Logger("isolated-concurrent-console", level=logging.DEBUG)
    logger.addHandler(handler)

    def worker(target):
        with target_context(target):
            for number in range(20):
                log_event(logger, logging.INFO, "Progress", count=number)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, ["lab-a", "lab-b", "lab-c", "lab-d"]))
    lines = stream.getvalue().splitlines()
    assert len(lines) == 80
    for target in ("lab-a", "lab-b", "lab-c", "lab-d"):
        own_lines = [line for line in lines if f"[{target}]" in line]
        assert [int(line.split("count=")[1]) for line in own_lines] == list(range(20))
        assert all(
            line.startswith("INFO    ") and line.count("Progress") == 1
            for line in own_lines
        )


def test_formatter_import_does_not_install_handlers_or_change_default_level():
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    GoConsoleFormatter()
    assert root.handlers == handlers
    assert root.level == level
