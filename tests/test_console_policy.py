"""Check explicit console selection with real file handlers and stage resets."""

from __future__ import annotations

import logging

import pytest

from openhound_collector_common.logging import ConsoleSettings, log_event


@pytest.fixture
def restore_loggers():
    saved = [
        (
            logging.getLogger(name),
            list(logging.getLogger(name).handlers),
            logging.getLogger(name).level,
            logging.getLogger(name).propagate,
        )
        for name in ("", "dlt", "openhound")
    ]
    formats = {
        handler: handler.formatter
        for logger, _handlers, _level, _propagate in saved
        for handler in logger.handlers
    }
    yield
    for logger, handlers, level, propagate in saved:
        for handler in logger.handlers:
            if getattr(handler, "_oh_owned_console", False):
                handler.close()
        logger.handlers = handlers
        logger.setLevel(level)
        logger.propagate = propagate
    for handler, formatter in formats.items():
        handler.setFormatter(formatter)


def test_silent_console_keeps_debug_file_records_and_redacts_them(
    tmp_path, capsys, restore_loggers
):
    file = tmp_path / "full.log"
    handler = logging.FileHandler(file, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("saved:%(levelname)s:%(message)s"))
    logging.getLogger().addHandler(handler)
    try:
        settings = ConsoleSettings(
            ("collector.example",), silent=True, secrets=("private-value",)
        )
        settings.apply()
        logging.getLogger("collector.example").debug(
            "Retained private-value diagnostic"
        )
        handler.flush()
        assert "saved:DEBUG:Retained <redacted> diagnostic" in file.read_text()
        assert "private-value" not in file.read_text()
        assert "private-value" not in repr(settings)
        assert capsys.readouterr().err == ""
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()


def test_repeated_stage_configuration_keeps_one_console_and_dependency_warnings(
    capsys, restore_loggers
):
    settings = ConsoleSettings(("collector.example",), no_color=True)
    settings.apply()
    # Model the framework replacing the DLT stage's handlers and propagation.
    dlt_logger = logging.getLogger("dlt")
    dlt_logger.addHandler(logging.StreamHandler())
    dlt_logger.propagate = False
    settings.apply()
    log_event(
        logging.getLogger("collector.example"),
        logging.INFO,
        "One record",
        target="lab-target",
        count=1,
    )
    dlt_logger.warning("Meaningful dependency failure")
    dlt_logger.info("Routine dependency chatter")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("One record") == 1
    assert "[lab-target] One record count=1" in captured.err
    assert captured.err.count("Meaningful dependency failure") == 1
    assert "Routine dependency chatter" not in captured.err
    assert (
        sum(
            bool(getattr(handler, "_oh_owned_console", False))
            for handler in logging.getLogger().handlers
        )
        == 1
    )
