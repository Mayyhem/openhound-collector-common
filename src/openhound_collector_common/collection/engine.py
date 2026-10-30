"""Ordered per-target phases over the shared target scheduler.

The collector supplies phase names, its context and rows, gating, log scopes and
output routing. This module knows no SCCM hosts, SQL ports or graph rules.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from queue import Queue
from typing import Generic, TypeVar

from ..dlt.source_bridge import broadcast_done
from ..logging import get_logger
from .errors import FatalCollectionError
from .scheduler import run_jobs
from .work_queue import WorkQueue

logger = get_logger(__name__)
Context = TypeVar("Context")
Row = TypeVar("Row")


@dataclass(frozen=True)
class Phase(Generic[Context, Row]):
    """One caller-defined collection step, with the tables it may write.

    Attributes:
        name: A collector-supplied phase label used for gating and diagnostics.
        streams: Names of the output tables the caller registers for this phase.
        run: Read-only generator receiving the target label and caller's context.
    """

    name: str
    streams: tuple[str, ...]
    run: Callable[[str, Context], Iterable[tuple[str, Row]]]


def run_one_target(
    target: str,
    context: Context,
    phases: Sequence[Phase[Context, Row]],
    streams: Mapping[str, Queue[Row]],
    should_run: Callable[[str, Phase[Context, Row], Context], bool] | None = None,
    phase_scope: Callable[[str, str], AbstractContextManager[object]] | None = None,
    *,
    emit: Callable[[str, Row], None] | None = None,
    is_stopped: Callable[[], bool] | None = None,
) -> None:
    """Run phases in order, preserving ordinary per-phase failure isolation.

    Cleanup failures and cancelled collection are fatal and must escape. A
    collector can supply its cancellable row writer instead of raw queue.put.
    """
    for phase in phases:
        if is_stopped is not None and is_stopped():
            logger.warning(
                "Not starting another phase on %s because collection stopped", target
            )
            return
        if should_run is not None and not should_run(target, phase, context):
            logger.debug(
                "Skipping phase %s on %s by the collector's policy", phase.name, target
            )
            continue
        scope = (
            phase_scope(target, phase.name)
            if phase_scope is not None
            else nullcontext()
        )
        with scope:
            try:
                rows = iter(phase.run(target, context))
                try:
                    for stream_name, row in rows:
                        if is_stopped is not None and is_stopped():
                            logger.warning(
                                "Not accepting another row from stopped target %s",
                                target,
                            )
                            return
                        if emit is not None:
                            emit(stream_name, row)
                        else:
                            streams[stream_name].put(row)
                finally:
                    close_rows = getattr(rows, "close", None)
                    if callable(close_rows):
                        close_rows()
                    # A plain list iterator owns no generator/provider cleanup.
            except FatalCollectionError:
                logger.exception("Fatal phase failure in %s on %s", phase.name, target)
                raise
            except Exception:
                logger.exception(
                    "Phase %s failed on %s; continuing other phases", phase.name, target
                )


def run_pipeline(
    work_queue: WorkQueue,
    context: Context,
    phases: Sequence[Phase[Context, Row]],
    streams: dict[str, Queue[Row]],
    max_workers: int,
    should_run: Callable[[str, Phase[Context, Row], Context], bool] | None = None,
    phase_scope: Callable[[str, str], AbstractContextManager[object]] | None = None,
    on_target_complete: Callable[[str], None] | None = None,
    *,
    emit: Callable[[str, Row], None] | None = None,
    finish: Callable[[], None] | None = None,
    on_failure: Callable[[BaseException], None] | None = None,
) -> None:
    """Collect recursive targets without losing worker failures or completion order."""
    failure: BaseException | None = None
    try:
        if max_workers < 1:
            logger.error("A phased worker pool requires at least one worker")
            raise ValueError("Phase workers must be positive")
        run_jobs(
            work_queue,
            lambda target: run_one_target(
                target,
                context,
                phases,
                streams,
                should_run,
                phase_scope,
                emit=emit,
                is_stopped=work_queue.stop_event.is_set,
            ),
            max_workers,
            on_target_complete=on_target_complete,
            on_failure=on_failure,
        )
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            if finish is not None:
                finish()
            else:
                broadcast_done(streams)
        except BaseException:
            logger.exception("Collection stream cleanup failed")
            if failure is None:
                raise
            # Preserve the first run failure; this cleanup failure is also logged.
