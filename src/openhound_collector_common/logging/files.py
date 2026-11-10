"""Run-owned diagnostics and grouped full logs, promoted from the SCCM collector.

Each unfinished group is spooled to a private file instead of retaining an
unbounded list of messages and live traceback objects in memory. Collectors
retain their own formats, phase names, and choices about when a target finishes.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import re
import shutil
import sys
import tempfile
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from threading import RLock
from types import TracebackType

from .console import GoConsoleFormatter, SecretRedactor, _RedactingFormatter
from .log_context import get_current_resource, get_current_target
from .log_context import (
    register_host_complete_callback,
    register_resource_complete_callback,
    unregister_host_complete_callback,
    unregister_resource_complete_callback,
)

logger = logging.getLogger(__name__)


class LogWriteError(OSError):
    """Required run diagnostics could not be written completely."""


class GoFileFormatter(GoConsoleFormatter):
    """Use the opt-in Go layout with redacted tracebacks in detailed files."""

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if record.exc_info and record.exc_info[0] is not None:
            text += "\n" + self.redactor.redact(self.formatException(record.exc_info))
        # Ordinary messages have no exception details to append.
        return text


class _WriteFailure:
    """Record a failed write once; avoid recursive errors through the same handler."""

    failure: str | None = None
    redactor: SecretRedactor

    def _failed(self, error: BaseException) -> None:
        if self.failure is None:
            self.failure = self.redactor.redact(str(error))
        # Report outside emit's handler lock at close. Logging recursively here
        # could deadlock two threads whose different file handlers both failed.

    def raise_if_failed(self) -> None:
        """Fail the owning command after its handlers/resources have been released."""
        if self.failure is not None:
            logger.error("Required run log write failed: %s", self.failure)
            raise LogWriteError(self.failure)
        # Successful diagnostics require no separate message for each write.


class DiagnosticFileHandler(logging.FileHandler, _WriteFailure):
    """Keep SCCM's warning/error tracebacks and companion exception debug lines.

    The file is created only for a qualifying record. Copies prevent traceback
    formatting from changing another console/file handler's view of the record.
    With ``write=False``, only warning/error counts are retained; no file is opened.
    """

    def __init__(
        self, path: Path, *, secrets: Iterable[str] = (), write: bool = True,
    ) -> None:
        super().__init__(str(path.resolve()), mode="w", encoding="utf-8", delay=True)
        self.redactor = SecretRedactor(secrets)
        self.failure = None
        self.warning_count = 0
        self.error_count = 0
        self._write = write
        self._has_closed = False
        self.setLevel(logging.DEBUG)
        self.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

    def format(self, record: logging.LogRecord) -> str:
        return self.redactor.redact(super().format(record))

    def emit(self, record: logging.LogRecord) -> None:
        if self.failure is not None:
            # The reported first write failure disables this broken handler.
            return
        active_exception = sys.exc_info()
        if record.levelno == logging.DEBUG and active_exception[0] is None:
            # Ordinary debug records belong in the full log, not the issues log.
            return
        if record.levelno != logging.DEBUG and record.levelno < logging.WARNING:
            # Retain SCCM's issues-file selection, independent of console detail.
            return
        if record.levelno >= logging.ERROR:
            self.error_count += 1
        elif record.levelno >= logging.WARNING:
            self.warning_count += 1
        # Companion debug records do not increase warning/error totals.
        if not self._write:
            # Count-only diagnostics deliberately perform no formatting or file I/O.
            return
        saved = copy.copy(record)
        saved.exc_text = None
        if not saved.exc_info and active_exception[0] is not None:
            saved.exc_info = active_exception
        # Explicit traceback information otherwise remains unchanged on the copy.
        try:
            Path(self.baseFilename).parent.mkdir(parents=True, exist_ok=True)
            super().emit(saved)
        except OSError as error:
            self._failed(error)

    def handleError(self, record: logging.LogRecord) -> None:
        # Standard logging's fallback can print the unredacted failed record.
        self._failed(sys.exc_info()[1] or OSError("Unknown diagnostics write failure"))

    def close(self) -> None:
        if self._has_closed:
            return  # Repeated shutdown must not raise the same failure again.
        self._has_closed = True
        try:
            super().close()
        except OSError as error:
            self._failed(error)
        self.raise_if_failed()


class _GroupedFormatter(logging.Formatter):
    """Retain ConfigManBearPig's existing ordered-file line layout by default."""

    def format(self, record: logging.LogRecord) -> str:
        label = f"{record.levelname:<8}"
        timestamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        text = f"{label} time={timestamp}, msg={record.getMessage()}"
        if record.exc_info and record.exc_info[0] is not None:
            text += "\n" + self.formatException(record.exc_info)
        # Records without exceptions have no traceback suffix.
        return text


class GroupedFileHandler(logging.Handler, _WriteFailure):
    """Write contiguous target/resource blocks in completion order.

    Only file names are held per unfinished group. Each complete formatted record
    goes straight to a private spool. A failed final write retains those spools
    and makes close fail; a clean close removes only its empty private directory.
    """

    def __init__(
        self,
        path: Path,
        level: int = logging.NOTSET,
        *,
        secrets: Iterable[str] = (),
        scratch_directory: Path | None = None,
        target_directory: Path | None = None,
    ) -> None:
        super().__init__(level)
        self._path = path.resolve()
        self.redactor = SecretRedactor(secrets)
        self.failure = None
        self._lock = RLock()
        self._pending: dict[str, Path] = {}
        self._has_closed = False
        self._spool_directory = Path(
            tempfile.mkdtemp(prefix="openhound-logs-", dir=scratch_directory)
        )
        self._target_directory = target_directory
        self.setFormatter(_GroupedFormatter())

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def emit(self, record: logging.LogRecord) -> None:
        if self.failure is not None:
            return  # The first reported failure already disabled this handler.
        try:
            resource = getattr(record, "_oh_resource", None) or get_current_resource()
            target = getattr(record, "_oh_target", None) or get_current_target()
            key = resource or target or "__root__"
            # Format/redact now; never retain a mutable record or traceback frame.
            text = self.redactor.redact(self.format(copy.copy(record))) + "\n"
            with self._lock:
                spool = self._pending.setdefault(
                    key, self._spool_directory / (self._digest(key) + ".log")
                )
                with spool.open("a", encoding="utf-8") as stream:
                    stream.write(text)
                if target and self._target_directory is not None:
                    safe_target = self.redactor.redact(target)
                    label = re.sub(r"[^A-Za-z0-9._-]", "_", safe_target)[:80]
                    self._target_directory.mkdir(parents=True, exist_ok=True)
                    destination = (
                        self._target_directory
                        / f"target_{label}_{self._digest(target)[:12]}.log"
                    )
                    with destination.open("a", encoding="utf-8") as stream:
                        stream.write(text)
                # Root/resource summaries do not create fake target log files.
        except (OSError, ValueError) as error:
            self._failed(error)

    def flush_resource(self, resource_name: str) -> None:
        """Publish one completed group's records without interleaving another group."""
        with self._lock:
            spool = self._pending.get(resource_name)
            if spool is None:
                return  # Empty/already-flushed groups have nothing to publish.
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as destination:
                    label = self.redactor.redact(resource_name)
                    destination.write(f"\n{'=' * 72}\n# {label}\n{'=' * 72}\n")
                    with spool.open(encoding="utf-8") as source:
                        shutil.copyfileobj(source, destination, length=65536)
                spool.unlink()
                del self._pending[resource_name]
            except OSError as error:
                self._failed(error)

    def flush_host(self, hostname: str) -> None:
        """Use the same completion API as the SCCM host callback."""
        self.flush_resource(hostname)

    def flush_all(self) -> None:
        """Publish complete buffered records after failure, interruption, or normal end."""
        with self._lock:
            for name in list(self._pending):
                self.flush_resource(name)

    def close(self) -> None:
        if self._has_closed:
            return  # Logging shutdown can close an already-released handler.
        self._has_closed = True
        self.flush_all()
        if not self._pending:
            try:
                self._spool_directory.rmdir()
            except OSError as error:
                self._failed(error)
        else:
            logger.error(
                "Unpublished redacted log groups retained in %s", self._spool_directory
            )
        super().close()
        self.raise_if_failed()


class RunFileLogs:
    """Own handler attachment, completion callbacks, and namespace levels for a run.

    Call close from the command's finally block, or use this as a context manager.
    finish_collection can release the grouped full log while keeping issues alive
    through later stages, matching ConfigManBearPig's existing lifecycle.
    File choices default to enabled. Disabling issues output retains its counts;
    disabling full output allocates no spool or completion callbacks.
    """

    def __init__(
        self,
        directory: Path,
        *,
        run_id: str,
        stage: str = "collect",
        namespaces: tuple[str, ...],
        secrets: Iterable[str] = (),
        per_target: bool = False,
        scratch_directory: Path | None = None,
        formatter: logging.Formatter | None = None,
        write_full: bool = True,
        write_issues: bool = True,
    ) -> None:
        if (
            re.fullmatch(r"[A-Za-z0-9_-]+", run_id) is None
            or re.fullmatch(r"[A-Za-z0-9_-]+", stage) is None
        ):
            logger.error("Run log ID/stage must be nonempty safe filename labels")
            raise ValueError(
                "Run log ID/stage must contain only letters, numbers, underscores, and hyphens"
            )
        directory.mkdir(parents=True, exist_ok=True)
        secrets = tuple(secrets)
        self.run_id = run_id
        self.full_path = directory / f"{stage}_full_{run_id}.log"
        self.issues_path = directory / f"{stage}_issues_{run_id}.log"
        self.write_issues = write_issues
        self.target_directory = (
            directory / f"{stage}_targets_{run_id}" if per_target and write_full else None
        )
        self.full = (
            GroupedFileHandler(
                self.full_path,
                logging.DEBUG,
                secrets=secrets,
                scratch_directory=scratch_directory,
                target_directory=self.target_directory,
            )
            if write_full else None
        )
        self.issues = DiagnosticFileHandler(self.issues_path, secrets=secrets, write=write_issues)
        if formatter is not None and self.full is not None:
            self.full.setFormatter(formatter)
        # CMBP keeps the promoted default format when none is supplied.
        self._namespaces = namespaces
        self._secrets = secrets
        self._formats: dict[logging.Handler, logging.Formatter | None] = {}
        self._levels: list[tuple[logging.Logger, int]] = []
        self._started = False
        self._collection_finished = False
        self._closed = False

    @property
    def owned_log_paths(self) -> tuple[Path, ...]:
        """Expose only this run's full/issues/target files and private log spool."""
        paths: list[Path] = []
        if self.full is not None:
            paths.extend((self.full_path, self.full._spool_directory))
        # Disabled outputs have no files to own or count toward log-space limits.
        if self.write_issues:
            paths.append(self.issues_path)
        if self.target_directory is not None:
            paths.append(self.target_directory)
        return tuple(paths)

    def __enter__(self) -> RunFileLogs:
        if self._started or self._closed:
            logger.error(
                "A file-log session cannot be started twice or reused after closing"
            )
            raise RuntimeError("RunFileLogs is a single-use session")
        self._started = True
        for name in ("", "dlt", "openhound"):
            for handler in logging.getLogger(name).handlers:
                original = handler.formatter
                self._formats[handler] = original
                handler.setFormatter(
                    _RedactingFormatter(
                        original or logging.Formatter("%(message)s"), self._secrets
                    )
                )
        for name in self._namespaces:
            namespace = logging.getLogger(name)
            self._levels.append((namespace, namespace.level))
            namespace.setLevel(logging.DEBUG)
        if self.full is not None:
            logging.root.addHandler(self.full)
            register_host_complete_callback(self.full.flush_host)
            register_resource_complete_callback(self.full.flush_resource)
        # A disabled full log has no handler, spool, or callbacks to attach.
        logging.root.addHandler(self.issues)
        return self

    def finish_collection(self) -> None:
        """Flush/release full logging, retaining issues for chained stages."""
        if self._collection_finished:
            return  # Repeated cleanup must not unregister another session's hooks.
        self._collection_finished = True
        if self.full is not None:
            unregister_host_complete_callback(self.full.flush_host)
            unregister_resource_complete_callback(self.full.flush_resource)
            logging.root.removeHandler(self.full)
        # Namespace restoration also applies when only counts were requested.
        for namespace, level in self._levels:
            namespace.setLevel(level)
        if self.full is not None:
            self.full.close()
        # There is no full-log handler to release when its output is disabled.

    def close(self) -> None:
        """Release both handlers even when flushing one of them fails."""
        if self._closed:
            return  # Safe under a second finally/shutdown path.
        self._closed = True
        try:
            self.finish_collection()
        finally:
            logging.root.removeHandler(self.issues)
            try:
                self.issues.close()
            finally:
                for handler, formatter in self._formats.items():
                    handler.setFormatter(formatter)

    def __exit__(
        self,
        error_type: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # A required-log failure must also override an otherwise partial exit.
        # Python retains any original exception as the failure's context.
        self.close()
