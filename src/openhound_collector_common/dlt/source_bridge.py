# Generalized from sccm/sccm/src/openhound_sccm/source.py (the push->pull stream
# helpers + the EXTRACT__WORKERS bump in sccm/.../main.py::_run_per_host_stage).
# SCCM-specific names (per-host phases, discovery resources, AD caches) are
# stripped; only the collector-agnostic bridge between a producer thread and the
# DLT extract pass remains. The table list and the producer are injected by the
# caller.
"""Push -> pull bridge between a producer thread and DLT emit resources.

DLT pulls rows: an ``@app.resource`` is a generator the extract pass iterates.
But a collector that connects to live targets naturally *pushes* rows (one
worker thread per target, calling into SQL and yielding ``(table, row)`` pairs).
This module bridges the two models with a registry of bounded per-table queues:

* The **producer** (a worker pool on a background thread) ``put``s each row onto
  the queue for its table, and at quiescence broadcasts a :data:`DONE` sentinel
  to every queue.
* Each **emit resource** is a DLT generator that drains exactly one table's
  queue via :func:`drain_stream` (a *blocking* ``get`` — an empty queue means
  "wait for more", not "stop"; only :data:`DONE` ends it).

Because the queues are bounded, a producer that outruns the extract pass simply
waits on ``put`` until a slot frees — flat memory regardless of row volume.

Concurrency note (the deadlock this guards against): each emit resource blocks
on its queue until :data:`DONE`, so it holds one DLT extract worker for the
whole run. DLT defaults to 5 workers; with more tables than workers, an
undrained table would wedge its bounded queue and deadlock the producer. Build
the emit resources with ``parallelized=True`` (each drains in its own thread)
**and** raise ``EXTRACT__WORKERS`` to at least one-per-table for the run via
:func:`extract_workers_for`. Both are required.

A :class:`StreamBridge` instance owns one run's registry; nothing is module-
global, so two collectors (or two tests) can each hold their own bridge.
"""
from __future__ import annotations

import contextlib
import logging
import os
import queue as _queue
from typing import Callable, Iterable, Iterator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# End-of-stream marker (generalized from sccm/.../phased_pipeline/streams.py).
# The MSSQL collector has no multi-phase per-host engine, so the bridge carries
# its own minimal stream primitives rather than depend on a phased_pipeline
# package. A later port of SCCM's full engine can re-export DONE from here.
# ---------------------------------------------------------------------------
class _Done:
    """Type of the unique :data:`DONE` end-of-stream marker."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return "<DONE>"


# The one shared "no more rows are coming" marker. Compare with ``is DONE``.
DONE = _Done()


def build_streams(names: Iterable[str], maxsize: int) -> dict[str, _queue.Queue]:
    """Return a dict mapping each name to a fresh bounded queue of length *maxsize*."""
    return {name: _queue.Queue(maxsize=maxsize) for name in names}


def broadcast_done(streams: dict[str, _queue.Queue]) -> None:
    """Put the shared :data:`DONE` marker on every stream (blocking put)."""
    for stream in streams.values():
        stream.put(DONE)


class StreamBridge:
    """One collection run's per-table queue registry + emit-resource factory.

    A caller:

    1. Builds the bridge for its table list: ``bridge = StreamBridge(tables)``.
    2. Registers one DLT emit resource per table:
       ``resources = bridge.build_emit_resources(resource_decorator, columns_for)``
       and returns them from its ``@app.source``.
    3. On a background thread, runs its producer: pushes rows with
       :meth:`put` (or hands :attr:`streams` to a pool) and calls
       :meth:`broadcast_done` once every target is finished.
    4. Wraps the extract pass in :func:`extract_workers_for` so DLT has one
       worker per table.

    The bridge does not start threads or know about workers — the caller owns
    the producer. It only owns the queues and the drain/emit machinery.
    """

    def __init__(self, table_names: Iterable[str], *, maxsize: int = 1000) -> None:
        """Create one bounded queue per table name.

        Args:
            table_names: The set of raw-table names the producer will write. Each
                gets its own bounded queue and its own emit resource.
            maxsize: Per-queue capacity (backpressure bound). Defaults to 1000.
        """
        self._table_names: tuple[str, ...] = tuple(table_names)
        self.streams: dict[str, _queue.Queue] = build_streams(self._table_names, maxsize=maxsize)
        logger.debug("StreamBridge created with %d table queue(s) (maxsize=%d)",
                     len(self._table_names), maxsize)

    @property
    def table_names(self) -> tuple[str, ...]:
        """The table names this bridge manages (the emit-resource set)."""
        return self._table_names

    # -- producer side -----------------------------------------------------
    def put(self, table_name: str, row: dict) -> None:
        """Push one row onto *table_name*'s queue (blocks if the queue is full).

        Unknown table names are dropped with a warning rather than raising, so a
        producer bug can't crash the whole run mid-stream.
        """
        stream = self.streams.get(table_name)
        if stream is None:
            # A row for a table we never registered: log and drop. Raising here
            # would kill the producer thread and strand every other table.
            logger.warning("Dropping row for unregistered table %r", table_name)
            return
        stream.put(row)

    def broadcast_done(self) -> None:
        """Place :data:`DONE` on every queue so all emit resources can finish.

        Call once, after the producer has finished every target (quiescence).
        """
        logger.debug("Broadcasting DONE to %d table queue(s)", len(self.streams))
        broadcast_done(self.streams)

    def drain_to_unblock(self) -> None:
        """Discard any buffered rows from every queue without blocking.

        Used on the error path: if the extract pass died, the emit resources
        stopped draining, so a producer worker may be blocked on a full queue.
        Emptying the queues lets it make progress (and reach :meth:`broadcast_done`
        / finish) so the caller's ``join`` can't hang. A no-op when empty.
        """
        for stream in self.streams.values():
            try:
                while True:
                    stream.get_nowait()
            except _queue.Empty:
                pass

    # -- consumer (DLT) side ----------------------------------------------
    def drain_stream(self, table_name: str) -> Iterator[dict]:
        """Yield rows from one table's queue until :data:`DONE`.

        A *blocking* ``get`` makes an empty queue a wait, not an end: the
        resource stops only on :data:`DONE`, broadcast once at quiescence. This
        is the generator body of each emit resource.
        """
        stream = self.streams.get(table_name)
        if stream is None:
            # Defensive: an emit resource for a table the bridge doesn't know.
            logger.error("drain_stream called for unregistered table %r", table_name)
            return
        while True:
            item = stream.get()
            if item is DONE:
                logger.debug("Stream %r received DONE; closing emit resource", table_name)
                return
            yield item

    def build_emit_resources(
        self,
        resource_decorator: Callable,
        columns_for: Callable[[str], object],
    ) -> list:
        """Build one DLT emit resource per table, returning the bound resources.

        Args:
            resource_decorator: The extension's ``@app.resource`` (passed in so
                the shared lib never imports a specific app). Called as
                ``resource_decorator(name=table, parallelized=True,
                columns=columns_for(table))(generator_fn)``.
            columns_for: Maps a table name to its ``BaseAsset`` subclass (the
                ``columns=`` model the conformance tests require). The caller
                supplies this because the asset model is extension-specific.

        Returns:
            A list of bound DLT resources, ready to return from ``@app.source``.

        Each resource drains its own queue via :meth:`drain_stream`.
        ``parallelized=True`` is mandatory: a single-threaded round-robin
        extractor would block on the first emit resource whose queue is
        momentarily empty while another queue fills to capacity — a deadlock.
        Independent threads avoid that (paired with :func:`extract_workers_for`).
        """
        resources = []
        for table in self._table_names:
            resources.append(self._make_emit_resource(table, resource_decorator, columns_for))
        logger.debug("Built %d emit resource(s)", len(resources))
        return resources

    def _make_emit_resource(self, table_name: str, resource_decorator: Callable,
                            columns_for: Callable[[str], object]):
        """Build one ``parallelized`` emit resource that streams *table_name*."""
        bridge = self

        @resource_decorator(name=table_name, parallelized=True, columns=columns_for(table_name))
        def _emit():
            yield from bridge.drain_stream(table_name)

        return _emit


@contextlib.contextmanager
def extract_workers_for(table_count: int):
    """Temporarily raise DLT's extract worker/parallel-item caps for the run.

    Each emit resource holds one extract worker for the whole run (it blocks on
    its queue until DONE), so DLT needs at least one worker per table or an
    undrained table deadlocks. Raises ``EXTRACT__WORKERS`` to ``table_count + 2``
    (a small margin) and ``EXTRACT__MAX_PARALLEL_ITEMS`` to match, then restores
    the prior environment in ``finally`` so the bump never leaks past the run.

    Mirrors sccm/.../main.py::_run_per_host_stage. Use as::

        with extract_workers_for(len(tables)):
            collector.run(source)
    """
    overrides = {
        "EXTRACT__WORKERS": str(table_count + 2),
        "EXTRACT__MAX_PARALLEL_ITEMS": str(max(20, table_count + 2)),
    }
    previous = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    logger.debug("Raised EXTRACT workers to %s for %d table(s)",
                 overrides["EXTRACT__WORKERS"], table_count)
    try:
        yield
    finally:
        # Restore the prior environment exactly (delete keys that were unset).
        for key, prior in previous.items():
            if prior is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prior
        logger.debug("Restored EXTRACT worker environment after run")


__all__ = ["StreamBridge", "extract_workers_for", "DONE"]
