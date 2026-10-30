"""Go fan-out contracts through Python's existing logger and common formatter."""

import io
import logging

from openhound_collector_common.logging import (
    GoConsoleFormatter,
    log_event,
    phase_context,
)


def two_outputs(*, first_level=logging.INFO, second_level=logging.INFO):
    """Create an isolated logger; never change the application's logging setup."""
    logger = logging.Logger("reference-fanout", level=logging.DEBUG)
    streams = [io.StringIO(), io.StringIO()]
    for stream, level in zip(streams, (first_level, second_level), strict=True):
        handler = logging.StreamHandler(stream)
        handler.setLevel(level)
        handler.setFormatter(GoConsoleFormatter(color=False))
        logger.addHandler(handler)
    return logger, streams


def test_go_multi_handler_message_and_fields_reach_both_outputs():
    logger, streams = two_outputs()
    log_event(logger, logging.INFO, "test message", key="value")
    for stream in streams:
        assert "test message" in stream.getvalue()
        assert "key=value" in stream.getvalue()


def test_go_multi_handler_enabled_level_keeps_each_output_threshold():
    logger, streams = two_outputs(first_level=logging.ERROR, second_level=logging.DEBUG)
    assert logger.isEnabledFor(logging.DEBUG)
    logger.debug("debug only")
    assert "debug only" not in streams[0].getvalue()
    assert "debug only" in streams[1].getvalue()


def test_go_multi_handler_bound_target_is_rendered_by_both_outputs():
    logger, streams = two_outputs()
    bound = logging.LoggerAdapter(logger, {"target": "server1:1433"})
    bound.info("connected")
    for stream in streams:
        assert "[server1:1433]" in stream.getvalue()
        assert "connected" in stream.getvalue()


def test_go_multi_handler_grouping_keeps_the_existing_handlers_and_empty_context():
    logger, streams = two_outputs()
    original_handlers = tuple(logger.handlers)
    # Python groups operations through common's existing context rather than
    # allocating a parallel Go-style handler wrapper for the same job.
    with phase_context("mygroup"):
        logger.info("grouped")
        assert tuple(logger.handlers) == original_handlers
    with phase_context(""):
        logger.info("ungrouped")
        assert tuple(logger.handlers) == original_handlers
    for stream in streams:
        grouped, ungrouped = stream.getvalue().splitlines()
        assert "phase=mygroup" in grouped
        assert "phase=" not in ungrouped
