"""Create one private scratch directory and remove only that owned directory."""

from __future__ import annotations

import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ..logging import get_logger
from .resources import RunResources

logger = get_logger(__name__)


@contextmanager
def private_scratch(
    *,
    prefix: str,
    parent: str | Path | None = None,
    resources: RunResources | None = None,
) -> Iterator[Path]:
    """Use an explicit parent and register new scratch before any data is written."""
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", prefix):
        logger.error("The scratch prefix must be a plain directory-name prefix")
        raise ValueError("Invalid scratch directory prefix")
    selected_parent = Path(
        parent if parent is not None else tempfile.gettempdir()
    ).resolve()
    selected_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=prefix, dir=selected_parent) as directory:
        owned = Path(directory).resolve()
        if owned.parent != selected_parent:
            logger.error("The created scratch directory is outside its selected parent")
            raise OSError("Scratch directory is outside its selected parent")
        if resources is not None:
            resources.register_path(owned)
        logger.debug("Using private run scratch directory %s", owned)
        try:
            yield owned
        except BaseException:
            logger.exception("The stage failed; releasing its owned scratch directory")
            raise
        # TemporaryDirectory removes only the verified owned child, including
        # after failure. Final raw/graph output must never be placed in here.
