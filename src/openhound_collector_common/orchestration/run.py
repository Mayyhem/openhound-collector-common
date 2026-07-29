"""Chain a collector's preproc + convert stages in-process after collect.

This is the shareable half of an extension's "run everything" convenience flag.
It is deliberately framework-agnostic: it never imports ``openhound`` or ``dlt``
at runtime, and treats the app as a duck-typed object exposing ``name``,
``preprocessor``, and ``converter`` (exactly what ``openhound.core.app.OpenHound``
registers via its ``@app.preproc`` / ``@app.convert`` decorators). Every path is
derived from the single collect OUTPUT_PATH, matching the framework's own layout
so ``--run-all`` and the manual three-command workflow touch identical files.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # type hints only — never import the framework at runtime
    from openhound.core.app import OpenHound
    from openhound.core.progress import Progress

logger = logging.getLogger(__name__)

# The framework's chained-phase filesystem convention, kept in one place so both
# --run-all and any "next steps" hint agree. `lookup.duckdb` mirrors the core
# DEFAULT_LOOKUP_FILE; the dlt dataset dir is named after the pipeline/dataset,
# which is the app name; `graph` is the convert output dir.
_LOOKUP_DB_NAME = "lookup.duckdb"
_GRAPH_DIR_NAME = "graph"


@dataclass(frozen=True)
class StagePaths:
    """The three paths the preproc + convert stages read/write, derived from OUTPUT_PATH."""

    dataset_dir: Path  # convert input: the dlt dataset dir (OUTPUT_PATH / app.name)
    lookup_db: Path    # preproc output and convert lookup (OUTPUT_PATH / lookup.duckdb)
    graph_out: Path    # convert output dir (OUTPUT_PATH / graph)


def derive_stage_paths(app: "OpenHound", output_path: Path) -> StagePaths:
    """Derive the preproc/convert paths from the single collect OUTPUT_PATH.

    Matches what a collector's manual "next steps" hint prints, so the automated
    and manual workflows read/write the exact same locations.
    """
    return StagePaths(
        dataset_dir=output_path / app.name,
        lookup_db=output_path / _LOOKUP_DB_NAME,
        graph_out=output_path / _GRAPH_DIR_NAME,
    )


class _NullProgress:
    """Progress stand-in whose ``.value`` is None (maps to dlt's NULL_COLLECTOR).

    The framework reads progress inconsistently: ``Converter`` uses
    ``progress.value``, so a bare ``None`` would raise ``AttributeError`` there,
    while ``PreProcessor`` forwards the object straight to ``dlt.pipeline()``,
    which happily accepts ``None``. This shim lets "silent" satisfy the converter;
    a bare ``None`` satisfies the preprocessor. See ``run_end_to_end``.
    """

    value = None


def run_end_to_end(
    app: "OpenHound",
    output_path: Path,
    *,
    progress: "Optional[Progress]" = None,
) -> StagePaths:
    """Run *app*'s preproc then convert stages in-process, chained off one collect run.

    Assumes collect has already written its raw JSONL under *output_path*. Runs
    preprocess (builds the DuckDB lookup) then convert (emits the OpenGraph
    files). The chain stops immediately if a stage raises — the exception
    propagates unchanged so the caller can report it. Returns the derived paths.

    progress: a framework ``Progress`` member for a live tracker, or ``None`` for
    silent (dlt NULL_COLLECTOR). Applied per-stage because the framework stages
    consume it differently (see ``_NullProgress``).
    """
    # A hook can be missing if an extension registered collect but not preproc /
    # convert; without both there is nothing to chain, so fail loudly and early
    # (before touching disk) rather than half-running.
    if app.preprocessor is None:
        logger.error("Cannot run end-to-end for '%s': no preproc hook is registered.", app.name)
        raise RuntimeError(f"{app.name}: no preproc hook registered; cannot run end-to-end.")
    if app.converter is None:
        logger.error("Cannot run end-to-end for '%s': no convert hook is registered.", app.name)
        raise RuntimeError(f"{app.name}: no convert hook registered; cannot run end-to-end.")

    paths = derive_stage_paths(app, output_path)

    # Preprocess: PreProcessor forwards `progress` straight to dlt.pipeline(),
    # which accepts a Progress (a str Enum) or None — so pass it through as-is.
    logger.info("Preprocessing raw data into lookup DB: %s", paths.lookup_db)
    app.preprocessor(
        input_path=output_path,
        output_file=paths.lookup_db,
        progress=progress,
    )
    logger.info("Preprocess complete: %s", paths.lookup_db)

    # Convert: Converter reads `progress.value`, so a bare None would crash it;
    # wrap None in the .value=None shim. A real Progress member already has .value.
    if progress is None:
        convert_progress = _NullProgress()
        logger.debug("Convert progress silenced (dlt NULL_COLLECTOR).")
    else:
        convert_progress = progress
        logger.debug("Convert progress backend: %s", getattr(progress, "value", progress))

    logger.info("Converting collected data into OpenGraph: %s", paths.graph_out)
    app.converter(
        input_path=paths.dataset_dir,
        output_path=paths.graph_out,
        lookup_file=paths.lookup_db,
        progress=convert_progress,
    )
    logger.info("Convert complete. Graph written to: %s", paths.graph_out)

    return paths
