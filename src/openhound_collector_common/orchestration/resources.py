"""Sample a run's system memory and owned files, then request a coordinated stop.

This is a sampled guard, not a hard memory or byte ceiling. Callers register
output/scratch paths before writing, check before batches and archives, and retain
complete records. The guard never deletes data or terminates a worker.
"""

from __future__ import annotations

import math
import os
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from threading import Event, Lock, RLock, Thread
from typing import Literal

from ..logging import get_logger

logger = get_logger(__name__)
FileCategory = Literal["data", "logs", "archives"]


def parse_byte_size(value: str) -> int:
    """Parse positive B/KB/MB/GB/TB or explicit binary KiB/MiB/GiB/TiB sizes."""
    match = re.fullmatch(
        r"\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|KIB|MIB|GIB|TIB)?\s*",
        value,
        re.IGNORECASE,
    )
    if match is None:
        logger.error("Invalid data size; use a positive value such as 1GB or 1GiB")
        raise ValueError("Use a positive size such as 1GB or 1GiB")
    unit = (match[2] or "B").upper()
    powers = {
        "B": 1,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
        "TIB": 1024**4,
    }
    try:
        size = Decimal(match[1]) * powers[unit]
    except InvalidOperation as error:
        logger.error("Invalid data size")
        raise ValueError("Invalid data size") from error
    if size <= 0 or size != size.to_integral_value():
        logger.error("The data size must be a positive whole number of bytes")
        raise ValueError("The data size must be a positive whole number of bytes")
    return int(size)


def system_memory_percent() -> float:
    """Use psutil's system usage percentage on Windows and other supported hosts."""
    # psutil supplies one tested cross-platform definition: used memory is
    # calculated from available memory, rather than inconsistent free-page APIs.
    # Its BSD license is Apache-compatible; callers approved the compiled package.
    # Keep the untyped provider at this one boundary. Convert its result to a
    # float here and validate its range in sample() before trusting it.
    import psutil  # type: ignore[import-untyped]

    return float(psutil.virtual_memory().percent)


@dataclass(frozen=True)
class ResourceSnapshot:
    """Current and peak measurements; logs/ZIP copies are outside the data cap."""

    data_bytes: int = 0
    peak_data_bytes: int = 0
    log_bytes: int = 0
    archive_bytes: int = 0
    memory_percent: float = 0
    peak_memory_percent: float = 0

    def as_report(self) -> dict[str, int | float]:
        """Return safe numerical fields for a run status report."""
        return asdict(self)


@dataclass(frozen=True)
class _FileState:
    size: int
    changed_at_ns: int
    identity: int


class ResourceLimitReached(RuntimeError):
    """A sampled limit stopped this run; callers retain complete output."""


def _path_key(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def _files(root: Path) -> Iterator[tuple[Path, _FileState]]:
    """Walk owned paths without following a junction into another directory."""
    pending = [root]
    while pending:
        path = pending.pop()
        try:
            if path.is_symlink() or path.is_junction():
                logger.error(
                    "Resource accounting cannot follow linked output paths: %s", path
                )
                raise OSError("Resource accounting encountered a linked output path")
            state = path.stat()
            if path.is_dir():
                pending.extend(path.iterdir())
            else:
                yield path, _FileState(state.st_size, state.st_mtime_ns, state.st_ino)
        except FileNotFoundError:
            # Normal when an owned scratch file is renamed or removed during
            # the sample. Persistent access errors must escape instead.
            logger.debug(
                "An owned output/scratch path changed during resource sampling"
            )


def _default_category(path: Path) -> FileCategory:
    name = path.name.casefold()
    if name.endswith(".log"):
        return "logs"  # Run logs are reported separately, never charged as data.
    if name.endswith((".zip", ".zip.tmp")):
        return "archives"  # ZIPs duplicate the loose data; count their size separately.
    return "data"


class RunResources:
    """Measure paths registered before writing and signal this run's stop event.

    Existing unchanged files are excluded. A changed existing file counts at its
    full current size; callers should register only their declared artifacts,
    not an unrelated parent tree. Overlapping paths are counted once. The same
    object can span collection, scratch cleanup and graph stages, retaining peaks.
    """

    def __init__(
        self,
        *,
        stop_event: Event,
        max_data_bytes: int | None = None,
        memory_threshold: float | None = None,
        sample_seconds: float = 1,
        memory_reader: Callable[[], float] = system_memory_percent,
        classify: Callable[[Path], FileCategory] = _default_category,
    ) -> None:
        if max_data_bytes is not None and (
            isinstance(max_data_bytes, bool)
            or not isinstance(max_data_bytes, int)
            or max_data_bytes < 1
        ):
            logger.error("The run data limit must be a positive number of bytes")
            raise ValueError("The run data limit must be positive")
        if memory_threshold is not None and (
            isinstance(memory_threshold, bool)
            or not math.isfinite(memory_threshold)
            or not 0 < memory_threshold <= 100
        ):
            logger.error(
                "The system memory threshold must be greater than zero and at most 100"
            )
            raise ValueError(
                "The memory threshold must be greater than zero and at most 100"
            )
        if not math.isfinite(sample_seconds) or not 0 < sample_seconds <= 1:
            logger.error("Resource samples must run at least once per second")
            raise ValueError(
                "The resource sample interval must be positive and at most one second"
            )
        self.stop_event = stop_event
        self.max_data_bytes = max_data_bytes
        self.memory_threshold = memory_threshold
        self.sample_seconds = sample_seconds
        self._memory_reader = memory_reader
        self._classify = classify
        self._guard = RLock()
        self._sample_guard = Lock()
        self._paths: dict[str, Path] = {}
        self._categories: dict[str, tuple[Path, FileCategory]] = {}
        self._previous: dict[str, _FileState] = {}
        self._snapshot = ResourceSnapshot()
        self._done = Event()
        self._thread: Thread | None = None
        self._failure: BaseException | None = None
        self._interrupts: dict[object, tuple[str, Callable[[], None]]] = {}
        self.stop_reason: str | None = None
        self.stop_category: Literal["memory", "data"] | None = None

    def register_path(
        self,
        path: str | Path,
        *,
        include_existing: bool = False,
        category: FileCategory | None = None,
    ) -> None:
        """Register before writing; adopt existing data only after proving its owner.

        A saved-data stage may explicitly adopt raw files already verified as
        belonging to this run. Normal registration excludes unrelated old files.
        """
        selected = Path(path).absolute()
        key = _path_key(selected)
        if category is not None and category not in ("data", "logs", "archives"):
            logger.error("An owned resource path needs a known file category")
            raise ValueError("Invalid owned resource path category")
        with self._guard:
            if category is not None:
                self._categories[key] = (selected, category)
            if key in self._paths:
                if include_existing:
                    for file, state in _files(selected):
                        self._previous.pop(_path_key(file), None)
                return  # The existing baseline must not absorb newly written files.
            # Overlapping roots share their first baseline, so registration
            # order cannot erase files already established as new run output.
            existing_roots = tuple(self._paths.values())
            for file, state in _files(selected):
                if include_existing:
                    self._previous.pop(_path_key(file), None)
                elif not any(file.is_relative_to(root) for root in existing_roots):
                    self._previous.setdefault(_path_key(file), state)
            self._paths[key] = selected
            logger.debug("Tracking run resource path %s", selected)

    @property
    def snapshot(self) -> ResourceSnapshot:
        """Return a consistent immutable measurement, including retained peaks."""
        with self._guard:
            return self._snapshot

    def sample(self) -> ResourceSnapshot:
        """Measure now; a reached limit sets the stop event without deleting data."""
        with self._sample_guard:
            memory = self._memory_reader()
            if not math.isfinite(memory) or not 0 <= memory <= 100:
                logger.error("The system memory reader returned an invalid percentage")
                raise ValueError("Invalid system memory measurement")
            with self._guard:
                paths = tuple(self._paths.values())
                previous = dict(self._previous)
                categories = sorted(
                    self._categories.values(),
                    key=lambda value: len(value[0].parts),
                    reverse=True,
                )
            totals: dict[FileCategory, int] = {"data": 0, "logs": 0, "archives": 0}
            seen: set[str] = set()
            for root in paths:
                for file, state in _files(root):
                    key = _path_key(file)
                    if key in seen or previous.get(key) == state:
                        continue  # Exclude unchanged old files and overlapping roots.
                    seen.add(key)
                    category = next(
                        (
                            kind
                            for path, kind in categories
                            if file == path or file.is_relative_to(path)
                        ),
                        None,
                    )
                    if category is None:
                        category = self._classify(file)
                    if category not in totals:
                        logger.error(
                            "The resource file classifier returned an unknown category"
                        )
                        raise ValueError("Invalid resource file category")
                    totals[category] += state.size
            should_interrupt = False
            with self._guard:
                self._snapshot = ResourceSnapshot(
                    totals["data"],
                    max(self._snapshot.peak_data_bytes, totals["data"]),
                    totals["logs"],
                    totals["archives"],
                    memory,
                    max(self._snapshot.peak_memory_percent, memory),
                )
                if self.stop_reason is None:
                    if (
                        self.memory_threshold is not None
                        and memory >= self.memory_threshold
                    ):
                        self.stop_category = "memory"
                        self.stop_reason = f"System memory reached the {self.memory_threshold:g}% threshold"
                    elif (
                        self.max_data_bytes is not None
                        and totals["data"] >= self.max_data_bytes
                    ):
                        self.stop_category = "data"
                        self.stop_reason = f"Generated data reached the {self.max_data_bytes}-byte limit"
                    # Healthy samples are deliberately quiet.
                    if self.stop_reason is not None:
                        logger.warning(
                            "%s; stopping new work and retaining complete records",
                            self.stop_reason,
                        )
                        self.stop_event.set()
                        should_interrupt = True
                snapshot = self._snapshot
            if should_interrupt:
                self._interrupt_owned_operations()
            return snapshot

    def _interrupt_owned_operations(self) -> None:
        with self._guard:
            active = tuple(self._interrupts.values())
        for label, interrupt in active:
            try:
                interrupt()
            except BaseException as error:
                logger.exception(
                    "Resource stop could not interrupt %s; waiting for its owner", label
                )
                with self._guard:
                    if self._failure is None:
                        self._failure = error
                self.stop_event.set()

    @contextmanager
    def interruptible(
        self, label: str, interrupt: Callable[[], None]
    ) -> Iterator[None]:
        """Register an owned provider's stop call only while that operation runs.

        The short guard prevents a late callback from interrupting the provider
        after its owner left this scope. The callback must support calls from a
        second thread, such as DuckDB's documented connection.interrupt().
        """
        self.check()
        token = object()
        finished = Event()
        guard = Lock()

        def request() -> None:
            with guard:
                if finished.is_set():
                    return  # Its owner already finished; never interrupt its next user.
                logger.warning("Requesting resource-limit interruption of %s", label)
                interrupt()

        with self._guard:
            self._interrupts[token] = (label, request)
        try:
            self.check()
            yield
        finally:
            with guard:
                finished.set()
            with self._guard:
                self._interrupts.pop(token, None)

    def check(self, *, sample_now: bool = False) -> None:
        """Check before a batch/archive; measurement failure is a failed run."""
        if sample_now:
            self.sample()
        with self._guard:
            if self._failure is not None:
                logger.error(
                    "Run resource measurements failed; limits cannot be verified"
                )
                raise RuntimeError(
                    "Run resource measurements failed"
                ) from self._failure
            if self.stop_reason is not None:
                raise ResourceLimitReached(self.stop_reason)
        # Another caller may set stop_event; its reason belongs to that caller.

    def _watch(self) -> None:
        while not self._done.wait(self.sample_seconds):
            try:
                self.sample()
            except BaseException as error:
                with self._guard:
                    self._failure = error
                logger.exception(
                    "Run resource measurements failed; requesting collection stop"
                )
                self.stop_event.set()
                self._interrupt_owned_operations()
                return

    def __enter__(self) -> RunResources:
        if self._thread is not None:
            logger.error("A run resource monitor cannot be entered twice")
            raise RuntimeError("Resource monitor already started")
        self.sample()
        self._thread = Thread(
            target=self._watch, name="openhound-resources", daemon=False
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._done.set()
        if self._thread is not None:
            self._thread.join()
        with self._guard:
            if self._failure is not None and (
                exc_type is None or isinstance(exc_value, ResourceLimitReached)
            ):
                logger.error(
                    "The run failed because resource measurements could not finish"
                )
                raise RuntimeError(
                    "Run resource measurements failed"
                ) from self._failure
            # Preserve an existing stage failure; the measurement failure was logged.
