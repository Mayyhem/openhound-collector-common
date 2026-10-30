"""Inspect or remove only the reusable output artifacts named by a collector."""

from __future__ import annotations

import datetime
import logging
import shutil
from collections.abc import Sequence
from pathlib import Path

logger = logging.getLogger(__name__)


class OutputCleanupError(RuntimeError):
    """A previous output could not be safely removed; collection must not start."""


def _artifact_paths(output_path: Path, names: Sequence[str]) -> list[Path]:
    """Resolve and check every deletion target before removing any artifact."""
    root = output_path.resolve()
    paths = []
    for name in names:
        if not name or name in (".", "..") or Path(name).name != name:
            logger.error("Reusable artifact names must be direct child names")
            raise OutputCleanupError(
                "Reusable artifacts must be direct children of the output directory"
            )
        target = output_path / name
        resolved = target.resolve()
        if resolved == root or not resolved.is_relative_to(root):
            logger.error("Refusing cleanup of an artifact resolving outside %s", root)
            raise OutputCleanupError(
                f"Artifact {target} resolves outside the output directory"
            )
        paths.append(target)
    return paths


def prior_load_packages(output_path: Path, dataset_name: str) -> tuple[int, str | None]:
    """Return package count and oldest write time, not a count of previous runs."""
    dataset = _artifact_paths(output_path, (dataset_name,))[0]
    loads = dataset / "_dlt_loads"
    if not loads.is_dir():
        # A fresh or interrupted collection may have no load records yet.
        return 0, None
    files = [file for file in loads.iterdir() if file.is_file()]
    if not files:
        # An empty load directory contains no successful package to count.
        return 0, None
    oldest = min(file.stat().st_mtime for file in files)
    return len(files), datetime.datetime.fromtimestamp(oldest).strftime(
        "%Y-%m-%d %H:%M"
    )


def clean_previous_collection(
    output_path: Path,
    clean: bool,
    *,
    dataset_name: str,
    artifact_names: Sequence[str],
    logger: logging.Logger = logger,
    stale_warning: str = (
        "Those rows WILL be merged into this run's graph, and any table this run "
        "finds empty will keep the OLD rows entirely. Pass --clean to discard them first."
    ),
) -> None:
    """Warn about retained data, or remove exactly the caller's reusable artifacts.

    Logs and reports survive because the caller never lists them. Every resolved
    target is checked before the first removal, including Windows junctions and
    symbolic links. A locked file or failed deletion aborts collection visibly.
    """
    paths = _artifact_paths(output_path, artifact_names)
    prior, oldest = prior_load_packages(output_path, dataset_name)
    present = [path for path in paths if path.exists()]
    if not clean:
        if prior or present:
            logger.warning(
                "%s already contains a previous collection (%d dlt load package(s), "
                "oldest written %s; %s). %s",
                output_path,
                prior,
                oldest or "unknown",
                ", ".join(path.name for path in present) or "no dataset dir",
                stale_warning,
            )
        else:
            logger.debug(
                "%s holds no previous collection; nothing to clean", output_path
            )
        return
    if not present:
        logger.info(
            "--clean: %s holds no previous collection artifacts; nothing to remove",
            output_path,
        )
        return
    for target in present:
        try:
            if target.is_dir():
                # The resolved absolute target was checked above, before any
                # removals. shutil does not traverse nested Windows junctions.
                shutil.rmtree(target)
            else:
                # A listed file is owned reusable output, not a retained report.
                target.unlink()
            logger.info("--clean: removed %s", target)
        except OSError as error:
            logger.error("--clean could not remove %s: %s", target, error)
            raise OutputCleanupError(
                f"--clean could not remove {target}: {error}. Close anything holding it open, "
                "or delete it manually, then re-run."
            ) from error
    logger.info(
        "--clean: discarded %d prior load package(s) (oldest %s) from %s",
        prior,
        oldest or "unknown",
        output_path,
    )
