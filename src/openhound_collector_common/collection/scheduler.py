"""Run target jobs with bounded workers and visible background failures."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import TypeVar

from ..logging import get_logger
from .errors import FatalCollectionError
from .work_queue import WorkQueue

logger = get_logger(__name__)
Result = TypeVar("Result")


def run_jobs(
    work_queue: WorkQueue,
    run_target: Callable[[str], Result],
    max_workers: int,
    *,
    on_target_complete: Callable[[str], None] | None = None,
    on_failure: Callable[[BaseException], None] | None = None,
    raise_on_stop: bool = True,
) -> list[tuple[str, Result]]:
    """Join every job before returning results or raising the first failure.

    Zero workers runs on the calling thread; positive values create that many
    loop tasks. Each takes its next target when
    ready, avoiding an unbounded list of futures for a large scan. A completion
    callback runs before its queue slot is released, preserving discoveries made
    by that callback. Callers keep their own permission/error policies inside
    run_target; any exception escaping it is a run failure.
    """
    if (
        isinstance(max_workers, bool)
        or not isinstance(max_workers, int)
        or max_workers < 0
    ):
        logger.error("The target worker count must be a nonnegative integer")
        raise ValueError("Target workers must be a nonnegative integer")
    results: list[tuple[str, Result]] = []
    failures: list[BaseException] = []
    guard = Lock()

    def record_failure(error: BaseException) -> None:
        with guard:
            first = not failures
            failures.append(error)
        logger.error(
            "A target worker failed (%s)",
            type(error).__name__,
            exc_info=(type(error), error, error.__traceback__),
        )
        work_queue.stop("A worker failed; see the run logs")
        if first and on_failure is not None:
            try:
                on_failure(error)
            except BaseException as callback_error:
                # Keep the original error while making a failed stop callback
                # visible. All worker loops are still joined below.
                logger.error(
                    "The collection failure callback also failed (%s)",
                    type(callback_error).__name__,
                )
        # Later failures are logged but cannot replace the first cause.

    def take_targets() -> None:
        while True:
            target = work_queue.next()
            if target is None:
                return  # Quiescent or stopped; another job must not be started.
            try:
                result = run_target(target)
                with guard:
                    results.append((target, result))
            except BaseException as error:
                record_failure(error)
            finally:
                try:
                    if on_target_complete is not None:
                        on_target_complete(target)
                    # No callback means the caller has no per-target finalization.
                except BaseException as error:
                    record_failure(error)
                finally:
                    try:
                        work_queue.complete(target)
                    except BaseException as error:
                        record_failure(error)

    def worker() -> None:
        try:
            take_targets()
        except BaseException as error:
            # Failure to fetch the next target must stop peers immediately. If
            # only the joining thread noticed it, a peer blocked on output could
            # prevent that thread from ever reaching this worker's result.
            record_failure(error)

    if max_workers == 0:
        logger.debug("Running target jobs on the calling thread")
        worker()
    else:
        with ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="collector-target"
        ) as executor:
            workers = []
            try:
                for _ in range(max_workers):
                    workers.append(executor.submit(worker))
            except BaseException as error:
                # Joining already-started loops is still required if starting
                # another loop fails, including an interruption by the caller.
                record_failure(error)
            for future in workers:
                try:
                    future.result()
                except BaseException as error:
                    record_failure(error)
    if failures:
        raise failures[0]
    if work_queue.stop_event.is_set() and raise_on_stop:
        logger.error(
            "Target scheduling stopped before normal completion: %s",
            work_queue.stop_reason,
        )
        raise FatalCollectionError(
            work_queue.stop_reason or "Target scheduling stopped"
        )
    if work_queue.stop_event.is_set():
        logger.warning("Returning finished target results after the caller's requested stop")
    return results
