# Generalized from sccm/sccm/src/openhound_sccm/log_context.py — the full
# per-target/per-phase/per-resource logging-context machinery the SCCM extension
# proved out, promoted here so every collector (SCCM, MSSQL, future) shares one
# implementation. The two collector-specific bits are generalized, not dropped:
#   - the graph-build trace helpers (trace_node/edge/...) and the cache-with-log
#     decorator take a caller-supplied ``logger`` so each collector's records land
#     under its own logger namespace (SCCM keeps thin wrappers binding
#     ``openhound_sccm.graph`` / ``openhound_sccm.lookup``),
#   - the completion-callback *registry* is a generic pub/sub; the collector's
#     specific callback (e.g. SCCM's ordered-log-file flush) is registered by the
#     collector, not defined here.
"""Per-target / per-phase / per-resource logging context for OpenHound collectors.

Adds, on top of stdlib :mod:`logging`:

1. A ``VERBOSE`` level (15, between INFO and DEBUG) + ``logger.verbose(...)``.
2. ``contextvars``-backed :func:`target_context` / :func:`phase_context` (and a
   per-resource contextvar). Whatever is on the stack at log-emission time is
   folded into the record as a ``[target][phase]`` prefix by :class:`LogContextFilter`.
3. :func:`with_log_context` — keeps the right phase/target/resource active across a
   call, including every ``yield`` of a dlt ``@app.resource`` generator (which dlt
   drives interleaved). On generator exhaustion it fires the resource-completion
   callbacks (a generic pub/sub a collector can hook, e.g. an ordered log handler).
4. Iterator helpers (:func:`per_host_iter` / :func:`per_pair_iter`), a
   :class:`VerboseLogger` type for ``.verbose()`` type-checking, a debug exc-info
   filter, a cache-with-log decorator, and OpenGraph build-trace helpers.

Stdlib only. No custom formatter and no replacement of the host framework's log
handlers: the filter rewrites ``record.msg`` so the framework's handler (Rich,
etc.) keeps rendering timestamps/levels/colors exactly as before.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import inspect
import logging
import sys
import threading
from typing import Any, Callable, Iterator, List, Optional, TypeVar


# ---------------------------------------------------------------------------
# VERBOSE log level — between INFO (20) and DEBUG (10). Importing this module
# installs the level globally and adds ``Logger.verbose()`` so collector code
# reads as ``logger.verbose(...)`` rather than ``logger.log(VERBOSE, ...)``.
# ---------------------------------------------------------------------------
VERBOSE = 15
logging.addLevelName(VERBOSE, "VERBOSE")


def _verbose(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    """``logger.verbose(...)`` shortcut for the VERBOSE level."""
    # Mirror stdlib's per-level guard so disabled VERBOSE calls stay cheap.
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, message, args, **kwargs)


if not hasattr(logging.Logger, "verbose"):
    # Only patch once — re-importing this module must not clobber the method.
    logging.Logger.verbose = _verbose  # type: ignore[attr-defined]


class VerboseLogger(logging.Logger):
    """A stdlib ``Logger`` plus the project's custom ``verbose`` level method.

    ``verbose`` is attached to ``logging.Logger`` at import time (above), but a
    static type checker can't see that runtime monkeypatch, so it flags every
    ``logger.verbose(...)`` call as an unknown attribute. Modules obtain their
    logger via :func:`get_logger` and get this type instead, so ``verbose`` is
    known while the full stdlib ``Logger`` interface is still inherited.
    """

    def verbose(self, message: str, *args: Any, **kwargs: Any) -> None: ...


def get_logger(name: str) -> VerboseLogger:
    """Return a module logger typed to include the custom ``verbose`` level.

    Drop-in for ``logging.getLogger(__name__)``; the returned object is the same
    plain ``Logger`` at runtime, only re-typed so ``.verbose(...)`` checks.
    """
    return logging.getLogger(name)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Per-target / per-phase / per-resource context vars
# ---------------------------------------------------------------------------
_current_target: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "openhound_collector_target", default=None,
)
_current_phase: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "openhound_collector_phase", default=None,
)
_current_resource: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "openhound_collector_resource", default=None,
)

# ---------------------------------------------------------------------------
# Completion-callback registries (generic pub/sub)
# ---------------------------------------------------------------------------
# Callables registered here are invoked with (resource_name) when a resource
# generator exhausts, and with (hostname) when a per-host target finishes all its
# phases. A collector hooks these for e.g. an ordered log handler that flushes a
# resource's / host's buffered records as a labelled block the moment it finishes.
_resource_complete_callbacks: List[Callable[[str], None]] = []
_resource_complete_callbacks_lock = threading.Lock()
_host_complete_callbacks: List[Callable[[str], None]] = []
_host_complete_callbacks_lock = threading.Lock()


def get_current_resource() -> Optional[str]:
    """Return the name of the resource generator currently executing, or None."""
    return _current_resource.get(None)


def get_current_target() -> Optional[str]:
    """Return the target (host/domain) currently in log context, or None."""
    return _current_target.get(None)


def get_current_phase() -> Optional[str]:
    """Return the phase currently in log context, or None."""
    return _current_phase.get(None)


def register_resource_complete_callback(cb: Callable[[str], None]) -> None:
    """Register *cb* to be called with the resource name when a generator exhausts."""
    with _resource_complete_callbacks_lock:
        if cb not in _resource_complete_callbacks:
            _resource_complete_callbacks.append(cb)


def unregister_resource_complete_callback(cb: Callable[[str], None]) -> None:
    """Remove a previously registered resource-completion callback."""
    with _resource_complete_callbacks_lock:
        try:
            _resource_complete_callbacks.remove(cb)
        except ValueError:
            pass


def register_host_complete_callback(cb: Callable[[str], None]) -> None:
    """Register *cb* to be called with the hostname when a target finishes all phases."""
    with _host_complete_callbacks_lock:
        if cb not in _host_complete_callbacks:
            _host_complete_callbacks.append(cb)


def unregister_host_complete_callback(cb: Callable[[str], None]) -> None:
    """Remove a previously registered host-completion callback."""
    with _host_complete_callbacks_lock:
        try:
            _host_complete_callbacks.remove(cb)
        except ValueError:
            pass


def fire_host_complete(hostname: str) -> None:
    """Notify every registered host-completion callback that *hostname* is done.

    Suitable as a per-host engine's ``on_target_complete``; runs in worker threads,
    so callbacks must be thread-safe. Exceptions are swallowed so a logging hiccup
    never aborts collection.
    """
    with _host_complete_callbacks_lock:
        callbacks = list(_host_complete_callbacks)
    for cb in callbacks:
        try:
            cb(hostname)
        except Exception:
            pass


@contextlib.contextmanager
def target_context(target: Optional[str]) -> Iterator[None]:
    """Push *target* onto the log-context stack for the duration of the block.

    Reentrant: nested blocks shadow the outer value and restore it on exit.
    """
    token = _current_target.set(target)
    try:
        yield
    finally:
        _current_target.reset(token)


@contextlib.contextmanager
def phase_context(phase: Optional[str]) -> Iterator[None]:
    """Push *phase* onto the log-context stack for the duration of the block."""
    token = _current_phase.set(phase)
    try:
        yield
    finally:
        _current_phase.reset(token)


# ---------------------------------------------------------------------------
# Filter that folds the [target][phase] prefix into the message text
# ---------------------------------------------------------------------------
class LogContextFilter(logging.Filter):
    """Prepend ``[target][phase]`` (whichever are set) to every record's message
    so the framework's handler renders it inline. Install once via
    :func:`install_filter`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # The same LogRecord may pass through multiple handlers; mutating
        # record.msg each time would duplicate the prefix, so a sentinel attribute
        # short-circuits reruns.
        if getattr(record, "_oh_prefixed", False):
            return True
        target = _current_target.get(None)
        phase = _current_phase.get(None)
        if not target and not phase:
            return True
        parts = []
        if target:
            parts.append(f"[{target}]")
        if phase:
            parts.append(f"[{phase}]")
        prefix = "".join(parts) + " "
        # Prepend to the *format string* only; record.args stay untouched so
        # percent-style substitution in getMessage() still works.
        record.msg = prefix + str(record.msg)
        record._oh_prefixed = True  # type: ignore[attr-defined]
        return True


_FILTER_SINGLETON = LogContextFilter()


class _DebugExcInfoFilter(logging.Filter):
    """Inject ``exc_info`` into WARNING+ records emitted inside an active exception
    handler when the root logger is at DEBUG level.

    Bridges the common "a warning without exc_info + a companion debug line"
    pattern, making the warning automatically carry the traceback in debug mode. A
    sentinel attribute prevents double-injection across multiple handlers.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if (
            record.levelno >= logging.WARNING
            and not record.exc_info
            and not getattr(record, "_oh_exc_injected", False)
            and logging.root.isEnabledFor(logging.DEBUG)
        ):
            exc = sys.exc_info()
            if exc[0] is not None and exc[0] is not StopIteration:
                record.exc_info = exc
                record._oh_exc_injected = True  # type: ignore[attr-defined]
        return True


_EXC_INFO_FILTER_SINGLETON = _DebugExcInfoFilter()


def install_filter() -> None:
    """Install the ``[target][phase]`` prefix filter (and the debug exc-info filter)
    on the root logger, and tidy any ``RichHandler`` found.

    Idempotent: re-running adds each singleton at most once. Filters are also added
    to the root and ``dlt`` loggers' handlers, because some handlers (notably
    RichHandler) have historically ignored logger-level filters. Where a Rich
    handler is found, two attribute writes (no framework code edits) keep the
    bracketed prefix renderable: turn ``markup`` off (so ``[host.example.com]``
    isn't mis-parsed as Rich markup and dropped) and hide the trailing
    ``file.py:NN`` column (which steals width and wraps long lines).
    """
    root = logging.getLogger()
    if _FILTER_SINGLETON not in root.filters:
        root.addFilter(_FILTER_SINGLETON)
    if _EXC_INFO_FILTER_SINGLETON not in root.filters:
        root.addFilter(_EXC_INFO_FILTER_SINGLETON)
    for logger_name in ("", "dlt"):
        target_logger = logging.getLogger(logger_name)
        for handler in target_logger.handlers:
            if _FILTER_SINGLETON not in handler.filters:
                handler.addFilter(_FILTER_SINGLETON)
            if _EXC_INFO_FILTER_SINGLETON not in handler.filters:
                handler.addFilter(_EXC_INFO_FILTER_SINGLETON)
            # Duck-typed Rich-handler tidy-up so we need not import rich here. The getattr
            # guard is the type check; logging.Handler has no `markup`, which is exactly
            # why the attribute is probed rather than assumed.
            if getattr(handler, "markup", False):
                handler.markup = False  # type: ignore[attr-defined]
            log_render = getattr(handler, "_log_render", None)
            if log_render is not None and hasattr(log_render, "show_path"):
                log_render.show_path = False


# ---------------------------------------------------------------------------
# Decorator factory
# ---------------------------------------------------------------------------
_F = TypeVar("_F", bound=Callable)


def with_log_context(
    *,
    phase: Optional[str] = None,
    target: Optional[str] = None,
    target_from_ctx_attr: Optional[str] = None,
    target_from_ctx_domain: bool = False,
) -> Callable[[_F], _F]:
    """Decorator that pushes a phase/target/resource log context around a call.

    Works for plain functions and generators. The contextvars are active for the
    whole call (including across every ``yield`` of a generator, which dlt drives
    interleaved) so any ``logger.*`` call in the body sees the right context.

    *target* pins a fixed target string. *target_from_ctx_attr* reads the target
    from that attribute of the call's first positional arg / ``ctx`` kwarg (e.g.
    ``"domain"``). *target_from_ctx_domain=True* is a convenience alias for
    ``target_from_ctx_attr="domain"`` (kept for the SCCM call sites).

    Apply BELOW a framework resource decorator so the framework wraps our wrapper::

        @app.resource(name="ldap_computers", columns=Computer)
        @with_log_context(phase="LDAP", target_from_ctx_domain=True)
        def ldap_computers(ctx): ...
    """
    attr = "domain" if target_from_ctx_domain else target_from_ctx_attr

    def _resolve_target(args: tuple, kwargs: dict) -> Optional[str]:
        if target is not None:
            return target
        if attr:
            ctx = args[0] if args else kwargs.get("ctx")
            if ctx is not None:
                value = getattr(ctx, attr, None)
                return str(value) if value else None
        return None

    def decorator(func: _F) -> _F:
        if inspect.isgeneratorfunction(func):
            @functools.wraps(func)
            def gen_wrapper(*args, **kwargs):
                # dlt drives resource generators interleaved (pull one value from
                # A, then B, then A). Pushing the context once around the whole
                # generator would let the last generator-to-enter leak its
                # contextvars into the others. So push/pop per next(): each
                # iteration sees its own values exclusively, and the yield happens
                # outside the context (no logging there) so no interleaved caller
                # observes ours.
                resolved_target = _resolve_target(args, kwargs)
                resource_name = func.__name__
                inner = func(*args, **kwargs)
                while True:
                    phase_token = _current_phase.set(phase) if phase is not None else None
                    target_token = (
                        _current_target.set(resolved_target) if resolved_target is not None else None
                    )
                    resource_token = _current_resource.set(resource_name)
                    try:
                        value = next(inner)
                    except StopIteration:
                        # Fire resource-completion callbacks before finally resets
                        # the resource contextvar, so lines emitted by a callback
                        # still carry the correct resource.
                        with _resource_complete_callbacks_lock:
                            cbs = list(_resource_complete_callbacks)
                        for cb in cbs:
                            try:
                                cb(resource_name)
                            except Exception:
                                pass
                        return
                    finally:
                        _current_resource.reset(resource_token)
                        if target_token is not None:
                            _current_target.reset(target_token)
                        if phase_token is not None:
                            _current_phase.reset(phase_token)
                    yield value
            return gen_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            resolved_target = _resolve_target(args, kwargs)
            phase_token = _current_phase.set(phase) if phase is not None else None
            target_token = (
                _current_target.set(resolved_target) if resolved_target is not None else None
            )
            try:
                return func(*args, **kwargs)
            finally:
                if target_token is not None:
                    _current_target.reset(target_token)
                if phase_token is not None:
                    _current_phase.reset(phase_token)
        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Per-host iteration helpers
# ---------------------------------------------------------------------------
def per_host_iter(items, *, key: str = "hostname") -> Iterator:
    """Iterate host-dicts, pushing ``target_context(host[key])`` around each yield.

    A plain ``for host in per_host_iter(...): logger.info(...)`` is auto-tagged
    with ``[hostname][PHASE]`` — no ``with`` block needed. Non-dict items are
    coerced via ``str()``; items with no value for *key* are yielded without a
    target push (so a malformed entry's "skipping" line still appears).
    """
    for h in items:
        if isinstance(h, dict):
            target = h.get(key)
        else:
            target = str(h) if h is not None else None
        if target:
            with target_context(str(target)):
                yield h
        else:
            yield h


def per_pair_iter(items) -> Iterator:
    """Iterate ``(target, value)`` pairs, pushing ``target_context(target)`` per pair.

    Useful for ``dict.items()`` where the key is already the host name.
    """
    for key, value in items:
        if key:
            with target_context(str(key)):
                yield key, value
        else:
            yield key, value


# ---------------------------------------------------------------------------
# Cache-with-verbose-logging — replaces ``@lru_cache`` on hot lookups so a
# collector can emit "Resolved X from cache" / "Resolving X" traces (lru_cache
# has no per-call hit indicator, so we keep our own dict and log explicitly).
# ---------------------------------------------------------------------------
def cached_with_log(label: str, *, logger: logging.Logger) -> Callable[[_F], _F]:
    """Decorate an instance method so every call logs at VERBOSE whether the lookup
    hit the cache or fell through to the underlying query.

    *label* is a short noun phrase for the log line (e.g. ``"Computer SID"``).
    *logger* is the collector's logger, so records land under its namespace.
    Replaces ``@lru_cache`` 1:1: drop-in for bound methods, keyed on the positional
    argument tuple.
    """

    def decorator(func: _F) -> _F:
        cache: dict[tuple, object] = {}

        @functools.wraps(func)
        def wrapper(self, *args):
            key = args
            verbose_enabled = logger.isEnabledFor(VERBOSE)
            if key in cache:
                if verbose_enabled:
                    key_text = ", ".join(repr(a) for a in args)
                    logger.verbose("Resolved %s %s from cache", label, key_text)  # type: ignore[attr-defined]
                return cache[key]
            if verbose_enabled:
                key_text = ", ".join(repr(a) for a in args)
                logger.verbose("Resolving %s %s via DuckDB", label, key_text)  # type: ignore[attr-defined]
            result = func(self, *args)
            cache[key] = result
            if result is None and verbose_enabled:
                logger.verbose("No %s found for %s", label, key_text)  # type: ignore[attr-defined]
            return result

        wrapper.cache_clear = lambda: cache.clear()  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# OpenGraph per-node / per-edge VERBOSE trace helpers. Any collector that emits
# nodes/edges can call these (passing its own graph logger); records land under
# that logger's namespace.
# ---------------------------------------------------------------------------
# Framework NodeProperties fields that are boilerplate, skipped by
# trace_node_with_properties. A caller can pass its own skip set.
_DEFAULT_TRACE_SKIP = frozenset({"node_id", "displayname", "name", "environmentid", "last_seen"})


def trace_node(kind: str, node_id: str, name: Optional[str], *, logger: logging.Logger) -> None:
    """Emit a ``Found existing <kind> node: <id> (<name>)`` VERBOSE line."""
    suffix = f" ({name})" if name else ""
    logger.verbose("Found existing %s node: %s%s", kind, node_id, suffix)  # type: ignore[attr-defined]


def trace_edge(kind: str, start: str, end: str, *, logger: logging.Logger) -> None:
    """Emit a ``Found existing edge X -[K]-> Y ...`` VERBOSE line (per yielded edge)."""
    logger.verbose(  # type: ignore[attr-defined]
        "Found existing edge %s -[%s]-> %s with identical properties, no changes made",
        start, kind, end,
    )


def trace_property_added(kind: str, node_id: str, prop_name: str, value, *, logger: logging.Logger) -> None:
    """Emit one ``    Added on <kind> <id>: <prop> = <value>`` VERBOSE line."""
    logger.verbose("    Added on %s %s: %s = %r", kind, node_id, prop_name, value)  # type: ignore[attr-defined]


def trace_node_with_properties(
    kind: str, node_id: str, name: Optional[str], properties: Any, *,
    logger: logging.Logger, skip: frozenset = _DEFAULT_TRACE_SKIP,
) -> None:
    """Emit a ``Found existing <kind> node`` line + one ``Added: <prop>`` line per
    populated (non-boilerplate, non-empty) dataclass field of *properties*.

    Walking dataclass fields is non-trivial per node, so short-circuit when VERBOSE
    is filtered (the convert hot path then pays nothing).
    """
    if not logger.isEnabledFor(VERBOSE):
        return
    import dataclasses

    trace_node(kind, node_id, name, logger=logger)
    if properties is None:
        return
    try:
        if not dataclasses.is_dataclass(properties):
            return
        for field in dataclasses.fields(properties):
            if field.name in skip:
                continue
            try:
                value = getattr(properties, field.name)
            except Exception:
                continue
            # Skip None / empty list / empty string; False and 0 are real values.
            if value is None or value == [] or value == "":
                continue
            trace_property_added(kind, node_id, field.name, value, logger=logger)
    except Exception:
        # A logging helper must never crash the caller.
        pass


__all__ = [
    "VERBOSE",
    "VerboseLogger",
    "get_logger",
    "LogContextFilter",
    "install_filter",
    "target_context",
    "phase_context",
    "with_log_context",
    "get_current_target",
    "get_current_phase",
    "get_current_resource",
    "register_resource_complete_callback",
    "unregister_resource_complete_callback",
    "register_host_complete_callback",
    "unregister_host_complete_callback",
    "fire_host_complete",
    "per_host_iter",
    "per_pair_iter",
    "cached_with_log",
    "trace_node",
    "trace_edge",
    "trace_property_added",
    "trace_node_with_properties",
]
