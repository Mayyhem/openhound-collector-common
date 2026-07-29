# The full per-target/per-phase/per-resource logging-context machinery, proven in
# the SCCM extension and promoted here (log_context.py) so every collector shares
# one implementation. The two collector-specific helpers (graph build-trace,
# cache-with-log) take a caller-supplied ``logger`` so each collector's records
# land under its own namespace.
"""Per-target / per-phase / per-resource logging context shared across OpenHound
collectors.

Importing :mod:`openhound_collector_common.logging.log_context` registers the
VERBOSE log level (+ ``logger.verbose(...)``) and exposes the ``[target][phase]``
contextvar tagging, ``with_log_context``, completion-callback registry, iterator
helpers, the debug exc-info filter, a cache-with-log decorator, and OpenGraph
build-trace helpers. This package re-exports the public names for convenience.
"""

from .log_context import (
    VERBOSE,
    LogContextFilter,
    VerboseLogger,
    cached_with_log,
    fire_host_complete,
    get_current_phase,
    get_current_resource,
    get_current_target,
    get_logger,
    install_filter,
    per_host_iter,
    per_pair_iter,
    phase_context,
    register_host_complete_callback,
    register_resource_complete_callback,
    target_context,
    trace_edge,
    trace_node,
    trace_node_with_properties,
    trace_property_added,
    unregister_host_complete_callback,
    unregister_resource_complete_callback,
    with_log_context,
)

__all__ = [
    "VERBOSE",
    "LogContextFilter",
    "VerboseLogger",
    "cached_with_log",
    "fire_host_complete",
    "get_current_phase",
    "get_current_resource",
    "get_current_target",
    "get_logger",
    "install_filter",
    "per_host_iter",
    "per_pair_iter",
    "phase_context",
    "register_host_complete_callback",
    "register_resource_complete_callback",
    "target_context",
    "trace_edge",
    "trace_node",
    "trace_node_with_properties",
    "trace_property_added",
    "unregister_host_complete_callback",
    "unregister_resource_complete_callback",
    "with_log_context",
]
