"""Share the existing optional progress choices without changing OpenHound core."""

from __future__ import annotations

import logging
from enum import Enum

from openhound.core.progress import Progress

logger = logging.getLogger(__name__)


class ProgressOption(str, Enum):
    """Off by default, with the framework's three trackers available explicitly."""

    off = "off"
    tqdm = "tqdm"
    log = "log"
    alive_progress = "alive_progress"


class SilentProgress:
    """Supply the .value attribute core expects while selecting DLT's no-op tracker."""

    value = None


def resolve_progress(
    choice: ProgressOption, *, logger: logging.Logger = logger
) -> Progress | SilentProgress:
    """Preserve SCCM's established choice and diagnostic wording for both consumers."""
    if choice is ProgressOption.off:
        logger.debug(
            "Progress output disabled (--progress off); using dlt NULL_COLLECTOR"
        )
        return SilentProgress()
    logger.debug("Progress backend selected: %s", choice.value)
    return Progress(choice.value)


def progress_backend(choice: object) -> str | None:
    """Validate a CLI/framework choice at the stage boundary and return its value."""
    value = getattr(choice, "value", choice)
    if value is None or value == "off":
        # An intentionally disabled tracker needs no additional message.
        return None
    if value not in ("tqdm", "log", "alive_progress"):
        logger.error("Unknown progress choice at the stage boundary")
        raise ValueError("Progress must be off, tqdm, log, or alive_progress")
    # The validated choices above are strings, including str-enum values.
    return str(value)
