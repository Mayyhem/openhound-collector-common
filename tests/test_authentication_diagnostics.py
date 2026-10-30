"""Provider debug packets are suppressed only in the authenticating thread."""

import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

from openhound_collector_common.logging.authentication import authentication_diagnostics


def test_provider_debug_filter_is_scoped_and_restored_even_on_failure(caplog):
    logger = logging.getLogger("impacket")
    original = list(logger.filters)
    caplog.set_level(logging.DEBUG, logger="impacket")
    with pytest.raises(RuntimeError):
        with authentication_diagnostics():
            logger.debug("private authentication packet")
            logger.warning("safe failed authentication outcome")
            with ThreadPoolExecutor(max_workers=1) as workers:
                workers.submit(logger.debug, "unrelated thread diagnostic").result()
            raise RuntimeError("controlled failure")
    assert logger.filters == original
    assert "private authentication packet" not in caplog.text
    assert "safe failed authentication outcome" in caplog.text
    assert "unrelated thread diagnostic" in caplog.text
