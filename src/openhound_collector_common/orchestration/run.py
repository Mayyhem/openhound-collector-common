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
import zipfile
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from .resources import RunResources

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
_DEFAULT_GRAPH_ZIP_NAME = "opengraph.zip"


@dataclass(frozen=True)
class StagePaths:
    """The paths the preproc + convert stages read/write, derived from OUTPUT_PATH.

    The first three are *derived* — pure functions of OUTPUT_PATH, knowable before
    anything runs. ``graph_zip`` is different: it is an *observation*, populated only
    by :func:`run_end_to_end` and only when an archive was actually written.
    """

    dataset_dir: Path  # convert input: the dlt dataset dir (OUTPUT_PATH / app.name)
    lookup_db: Path  # preproc output and convert lookup (OUTPUT_PATH / lookup.duckdb)
    graph_out: Path  # convert output dir (OUTPUT_PATH / graph)
    # The bundled archive run_end_to_end wrote, or None when none was (convert emitted
    # no *.json, or these paths were merely derived rather than run). Reporting the
    # archive that exists beats a caller reconstructing where one *should* be: the two
    # can disagree, and only this one is evidence. Defaulted so the three derived
    # fields remain the whole constructor for any caller that just wants locations.
    graph_zip: Optional[Path] = None


def derive_stage_paths(app: "OpenHound", output_path: Path) -> StagePaths:
    """Derive the preproc/convert paths from the single collect OUTPUT_PATH.

    Matches what a collector's manual "next steps" hint prints, so the automated
    and manual workflows read/write the exact same locations.

    ``graph_zip`` is left ``None``: nothing has run yet, so no archive exists to
    report. This function is also what a collector calls on the *failure* path to
    print resume commands, where claiming an archive would be actively wrong.
    """
    return StagePaths(
        dataset_dir=output_path / app.name,
        lookup_db=output_path / _LOOKUP_DB_NAME,
        graph_out=output_path / _GRAPH_DIR_NAME,
    )


def zip_graph_output(
    graph_dir: Path,
    archive_name: str = _DEFAULT_GRAPH_ZIP_NAME,
    *,
    resources: RunResources | None = None,
) -> Optional[Path]:
    """Bundle every *.json in *graph_dir* into a flat ``graph_dir/<archive_name>``.

    The archive stores each file by basename (no directory prefix), which is exactly
    the shape ``integration_testing.graph.load_graph`` reads back (``sorted(zf.namelist())``,
    ``.json`` only) and BloodHound File Ingest accepts — so the operator has one
    upload-ready artifact. The loose ``.json`` files are left in place (non-destructive),
    and only ``*.json`` are added, so a prior archive (any ``.zip``) is never nested in.

    *archive_name* is a parameter, not a constant, because this library is shared with the
    MSSQL collector — each collector names its own archive (this one passes a timestamped
    ``configmanbearpig_collection_<ts>.zip``). Returns the zip path, or ``None`` when there
    is nothing to bundle (a missing dir, or a dir with no ``*.json``) — those are no-ops,
    not errors, so a caller can call this unconditionally after convert.
    """
    if not graph_dir.is_dir():
        logger.debug(
            "Graph dir %s does not exist; no %s written.", graph_dir, archive_name
        )
        return None
    json_files = sorted(graph_dir.glob("*.json"))
    if not json_files:
        logger.warning("No *.json in %s; skipping %s.", graph_dir, archive_name)
        return None
    zip_path = graph_dir / archive_name
    if resources is not None:
        resources.register_path(graph_dir)
        resources.check(sample_now=True)
        with tempfile.NamedTemporaryFile(
            prefix=".archive-", suffix=".zip.tmp", dir=graph_dir, delete=False
        ) as temporary:
            owned = Path(temporary.name)
        try:
            with zipfile.ZipFile(
                owned, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for file in json_files:
                    resources.check()
                    with (
                        file.open("rb") as source,
                        archive.open(file.name, "w", force_zip64=True) as destination,
                    ):
                        while chunk := source.read(1024 * 1024):
                            resources.check()
                            destination.write(chunk)
            resources.check(sample_now=True)
            owned.replace(zip_path)
            resources.sample()
        finally:
            # Only this newly created temporary ZIP is removed on failure. The
            # complete loose files and any previous archive remain available.
            owned.unlink(missing_ok=True)
        logger.info("Bundled %d graph files into %s", len(json_files), zip_path)
        return zip_path
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in json_files:
            zf.write(f, arcname=f.name)  # arcname = basename -> flat archive
    logger.info("Bundled %d graph file(s) into %s", len(json_files), zip_path)
    return zip_path


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
    graph_zip_name: Optional[str] = None,
    resources: RunResources | None = None,
) -> StagePaths:
    """Run *app*'s preproc then convert stages in-process, chained off one collect run.

    Assumes collect has already written its raw JSONL under *output_path*. Runs
    preprocess (builds the DuckDB lookup) then convert (emits the OpenGraph
    files). The chain stops immediately if a stage raises — the exception
    propagates unchanged so the caller can report it. Returns the derived paths.

    progress: a framework ``Progress`` member for a live tracker, or ``None`` for
    silent (dlt NULL_COLLECTOR). Applied per-stage because the framework stages
    consume it differently (see ``_NullProgress``).
    graph_zip_name: basename for the bundled graph archive written into the graph
    dir after convert; defaults to ``<app.name>_collection.zip``. The archive that
    was actually written comes back on the returned ``StagePaths.graph_zip`` (``None``
    if convert emitted no ``*.json`` and there was nothing to bundle).
    """
    # A hook can be missing if an extension registered collect but not preproc /
    # convert; without both there is nothing to chain, so fail loudly and early
    # (before touching disk) rather than half-running.
    if app.preprocessor is None:
        logger.error(
            "Cannot run end-to-end for '%s': no preproc hook is registered.", app.name
        )
        raise RuntimeError(
            f"{app.name}: no preproc hook registered; cannot run end-to-end."
        )
    if app.converter is None:
        logger.error(
            "Cannot run end-to-end for '%s': no convert hook is registered.", app.name
        )
        raise RuntimeError(
            f"{app.name}: no convert hook registered; cannot run end-to-end."
        )

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
        logger.debug(
            "Convert progress backend: %s", getattr(progress, "value", progress)
        )

    logger.info("Converting collected data into OpenGraph: %s", paths.graph_out)
    app.converter(
        input_path=paths.dataset_dir,
        output_path=paths.graph_out,
        lookup_file=paths.lookup_db,
        progress=convert_progress,
    )
    logger.info("Convert complete. Graph written to: %s", paths.graph_out)
    # One upload-ready archive for BloodHound File Ingest; a no-op if convert wrote no json.
    # Collector-agnostic default name; the caller may pass a run-specific one.
    archive_name = graph_zip_name or f"{app.name}_collection.zip"
    graph_zip = (
        zip_graph_output(paths.graph_out, archive_name, resources=resources)
        if resources is not None
        else zip_graph_output(paths.graph_out, archive_name)
    )

    # Frozen dataclass, so hand back a new one carrying what was actually written.
    # Without this the archive path was unreportable: the caller knew only the name
    # it had asked for, and had to rebuild graph_out / name and re-test existence to
    # say where the upload artifact landed.
    return replace(paths, graph_zip=graph_zip)
