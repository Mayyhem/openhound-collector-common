"""Exercise grouped diagnostics, bounded message storage, and scoped cleanup."""

import logging
from pathlib import Path

import pytest

from openhound_collector_common.logging.console import (
    SecretRedactor,
    is_secret_field,
    log_event,
)
from openhound_collector_common.logging.files import (
    DiagnosticFileHandler,
    GoFileFormatter,
    GroupedFileHandler,
    LogWriteError,
    RunFileLogs,
)
from openhound_collector_common.logging.log_context import target_context


@pytest.mark.parametrize(
    "name",
    ["ntHash", "ldapPassword", "rawNTLMResponse", "keytabPath", "kerberosTicket"],
)
def test_structured_secret_names_cover_camel_case(name):
    assert is_secret_field(name)


def test_inline_passwords_with_at_signs_and_url_schemes_are_redacted():
    redactor = SecretRedactor()
    assert (
        redactor.redact("socks5://alice:p@ss@proxy:1080")
        == "socks5://alice:<redacted>@proxy:1080"
    )
    assert redactor.redact("alice:p@ss@sql:1433") == "alice:<redacted>@sql:1433"


def test_interleaved_targets_flush_as_complete_blocks_in_completion_order(tmp_path):
    handler = GroupedFileHandler(tmp_path / "full.log")
    for target, message in [
        ("one:1433", "one first"),
        ("two:51433", "two first"),
        ("one:1433", "one last"),
    ]:
        with target_context(target):
            handler.emit(
                logging.makeLogRecord(
                    {"msg": message, "levelno": logging.INFO, "levelname": "INFO"}
                )
            )
    handler.flush_host("two:51433")
    handler.flush_host("one:1433")
    handler.close()
    text = (tmp_path / "full.log").read_text(encoding="utf-8")
    assert text.index("two first") < text.index("one first") < text.index("one last")


def test_many_large_messages_are_spooled_without_retaining_records_or_arguments(
    tmp_path,
):
    handler = GroupedFileHandler(tmp_path / "full.log", scratch_directory=tmp_path)
    values = ["original"]
    for number in range(100):
        handler.emit(
            logging.makeLogRecord(
                {
                    "msg": "%s " + "x" * 10000,
                    "args": (values,),
                    "levelno": logging.DEBUG,
                    "levelname": "DEBUG",
                }
            )
        )
    values[0] = "changed after emission"
    assert len(handler._pending) == 1
    assert all(isinstance(value, Path) for value in handler._pending.values())
    assert next(iter(handler._pending.values())).stat().st_size > 1000000
    handler.close()
    text = (tmp_path / "full.log").read_text(encoding="utf-8")
    assert "changed after emission" not in text
    assert "original" in text
    assert not list(tmp_path.glob("openhound-logs-*"))


def test_target_files_distinguish_ports_instances_and_redact_file_names(tmp_path):
    handler = GroupedFileHandler(
        tmp_path / "full.log",
        secrets=("secret-value",),
        target_directory=tmp_path / "targets",
    )
    for target in ("sql:1433", "sql:51433\\REPORTS", "user:secret-value@sql:1433"):
        with target_context(target):
            handler.emit(
                logging.makeLogRecord(
                    {
                        "msg": "secret-value detail",
                        "levelno": logging.INFO,
                        "levelname": "INFO",
                    }
                )
            )
    handler.close()
    files = list((tmp_path / "targets").glob("*.log"))
    assert len(files) == 3
    assert any("51433_REPORTS" in file.name for file in files)
    assert all(
        "secret-value" not in file.name + file.read_text(encoding="utf-8")
        for file in files
    )


def test_issues_capture_active_exception_without_changing_the_shared_record(tmp_path):
    handler = DiagnosticFileHandler(tmp_path / "issues.log", secrets=("private-value",))
    record = logging.makeLogRecord(
        {"msg": "operation failed", "levelno": logging.WARNING}
    )
    try:
        raise ValueError("private-value provider error")
    except ValueError:
        handler.emit(record)
    handler.close()
    text = (tmp_path / "issues.log").read_text(encoding="utf-8")
    assert "ValueError" in text and "private-value" not in text
    assert record.exc_info is None and record.exc_text is None


def test_required_write_failure_preserves_spools_and_makes_close_fail(tmp_path):
    destination = tmp_path / "occupied-directory"
    destination.mkdir()
    handler = GroupedFileHandler(destination, scratch_directory=tmp_path)
    handler.emit(
        logging.makeLogRecord(
            {"msg": "complete record retained", "levelno": logging.ERROR}
        )
    )
    with pytest.raises(LogWriteError):
        handler.close()
    assert list(handler._spool_directory.glob("*.log"))
    handler.close()  # Repeated logging shutdown is safe.


def test_session_restores_handlers_levels_and_formatters_after_failure(tmp_path):
    root = logging.getLogger()
    namespace = logging.getLogger("test_run_file_logs")
    handlers = list(root.handlers)
    formatters = {handler: handler.formatter for handler in handlers}
    level = namespace.level
    with pytest.raises(RuntimeError, match="stage failed"):
        with RunFileLogs(
            tmp_path,
            run_id="known-run",
            namespaces=(namespace.name,),
            secrets=("private-value",),
            formatter=GoFileFormatter(secrets=("private-value",)),
        ) as files:
            namespace.debug("detailed private-value trace")
            try:
                raise RuntimeError("stage failed")
            except RuntimeError:
                namespace.warning("stage warning")
                raise
    assert root.handlers == handlers
    assert namespace.level == level
    assert all(handler.formatter is formatters[handler] for handler in handlers)
    full = files.full_path.read_text(encoding="utf-8")
    issues = files.issues_path.read_text(encoding="utf-8")
    assert "detailed" in full and "private-value" not in full + issues
    assert "RuntimeError: stage failed" in issues


def test_session_issues_survive_into_later_stages_without_duplicate_handlers(tmp_path):
    namespace = logging.getLogger("test_run_log_chain")
    original = list(logging.root.handlers)
    for run in ("first", "second"):
        with RunFileLogs(tmp_path, run_id=run, namespaces=(namespace.name,)) as files:
            namespace.debug("collection detail")
            files.finish_collection()
            namespace.warning("later stage warning")
        assert logging.root.handlers == original
        assert "later stage warning" in files.issues_path.read_text(encoding="utf-8")
        assert "later stage warning" not in files.full_path.read_text(encoding="utf-8")


def test_structured_fields_survive_detailed_files_with_secrets_removed(tmp_path):
    namespace = logging.getLogger("test_run_fields")
    with RunFileLogs(
        tmp_path,
        run_id="fields",
        namespaces=(namespace.name,),
        formatter=GoFileFormatter(),
    ) as files:
        log_event(
            namespace,
            logging.INFO,
            "Probe complete",
            rows=7,
            ntHash="must-never-appear",
        )
    text = files.full_path.read_text(encoding="utf-8")
    assert "rows=7" in text and "ntHash=<redacted>" in text
    assert "must-never-appear" not in text
