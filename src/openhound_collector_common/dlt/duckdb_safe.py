# Generalized from sccm/sccm/src/openhound_sccm/transforms.py (helpers _safe,
# _ensure_columns, _arr only).
#
# "Generalize" per design spec §2.1: kept the generic DuckDB-defense logic;
# stripped the SCCM-specific bits:
#   - SCCM's _safe baked in a WMI-vs-AdminService "sibling table" downgrade (a
#     missing wmi_<x> is only a DEBUG miss when adminservice_<x> exists). That
#     transport-mirror knowledge is SCCM-specific, so here a missing table is a
#     plain WARNING by default and the sibling-downgrade is OPT-IN via an
#     injectable callback (expected_miss),
#   - renamed to public, collector-agnostic names: safe_execute / ensure_columns
#     / arr_sql.
#
# Why these exist (the dlt column-dropping gotcha, design spec §14.3): dlt drops
# columns that are absent or all-NULL across a load, and snake_cases camelCase
# keys. A coalesce SELECT that references such a column then fails to compile with
# a DuckDB BinderException and — if wrapped in safe_execute — silently drops the
# whole source. ensure_columns pre-creates the referenced-but-absent columns as
# typed NULLs so the SELECT always binds; arr_sql normalizes a list column to
# VARCHAR[] whatever physical shape dlt gave it.
"""DuckDB-safe SQL helpers: run-and-log, missing-column backfill, and list
normalization, hardening preproc SQL against dlt's column dropping/renaming.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

import duckdb

_LOG = logging.getLogger(__name__)

# An expected-miss predicate: given the missing table name parsed from a DuckDB
# CatalogException, return True if that miss is expected/benign (log at DEBUG)
# rather than a real problem (log at WARNING). Collectors that have fallback
# "sibling" tables (e.g. one of two transports produces a table) supply one.
ExpectedMiss = Callable[[duckdb.DuckDBPyConnection, str], bool]


def safe_execute(
    con: duckdb.DuckDBPyConnection,
    label: str,
    sql: str,
    *,
    expected_miss: Optional[ExpectedMiss] = None,
    logger: Optional[logging.Logger] = None,
    raise_on_error: bool = False,
) -> None:
    """Run one SQL statement; log and continue if a source table is missing.

    A missing source table (DuckDB ``CatalogException``) is expected during early
    collection when not every source has produced its table yet, so it is logged
    and swallowed rather than raised.

    *expected_miss*, if given, is called with ``(con, missing_table_name)`` when a
    table is missing; returning ``True`` downgrades the log from WARNING to DEBUG.
    This lets a collector mark benign misses (e.g. "the other transport produced
    this data under a sibling table name") without baking that knowledge in here.
    Any non-catalog DuckDB error is logged at ERROR (it indicates a real SQL bug,
    not a not-yet-collected source).

    With *raise_on_error=True*, genuine SQL errors are re-raised after logging so
    a caller can report incomplete requested work. Missing source tables keep
    their existing handling. The default preserves existing consumers' behavior.

    On a missing source table this logs a one-line summary naming the label and the
    absent table. When the miss is *unexpected* a companion DEBUG record carries the
    full DuckDB exception -- its "Did you mean" guess and the SQL echo -- which is
    worth reading only when the absence is a surprise, e.g. a typo'd table name.

    *logger*, if given, is used for all log records instead of this module's logger
    — a consuming collector passes its own so the ``%(name)s`` field stays under its
    namespace (log parity). Defaults to this module's log.
    """
    log = logger or _LOG
    try:
        con.execute(sql)
    except duckdb.CatalogException as err:
        # Parse the missing table name from the message, e.g.
        # "Catalog Error: Table with name node_foo does not exist!"
        match = duckdb_missing_table_name(str(err))
        if match is None:
            # A catalog error that is NOT a missing source table -- a misspelled
            # function, an absent schema, a bad sequence. Those are coding errors,
            # so they take the loud path rather than being reported as an
            # uncollected source. Only "this table has not been produced yet" is
            # an expected absence; everything else is a bug worth seeing.
            log.error("transform %r failed: %s", label, err)
            if raise_on_error:
                raise
            # Existing consumers may choose to continue after the logged failure.
            return
        downgrade = False
        if expected_miss is not None:
            # Let the collector classify this miss as benign or not.
            try:
                downgrade = bool(expected_miss(con, match))
            except duckdb.Error:
                # If the classifier itself hits a DB error, stay safe and warn.
                downgrade = False
        if downgrade:
            # An expected absence needs no diagnosis: the summary already says
            # everything the exception would, so no companion detail record.
            log.debug("transform %r skipped: expected missing source table %r", label, match)
        else:
            # A missing source table is expected before all sources have run, so this
            # is a WARNING and not an ERROR. One line: DuckDB's exception carries a
            # "Did you mean" guess and a re-print of the failing SQL with a caret,
            # which turned every skipped transform into a five-line block.
            log.warning("transform %r skipped: source table %r does not exist", label, match)
            # The guess and the SQL echo only earn their space when the miss is a
            # SURPRISE -- that is when a typo'd table name is worth diagnosing.
            log.debug("transform %r: %s", label, err)
    except duckdb.Error as err:
        # Non-catalog error => a real SQL problem worth surfacing loudly.
        log.error("transform %r failed: %s", label, err)
        if raise_on_error:
            raise
        # Existing consumers may choose to continue after the logged failure.


def duckdb_missing_table_name(message: str) -> Optional[str]:
    """Parse the missing table name out of a DuckDB ``CatalogException`` message.

    Returns the bare table name (e.g. ``node_foo``) or ``None`` if it can't be
    found. Useful inside an ``expected_miss`` callback.
    """
    import re

    # Anchored on "Table with name" deliberately. DuckDB uses the same
    # "<thing> with name <x> does not exist!" shape for scalar functions, schemas,
    # sequences and more, so an unanchored match reported a misspelled function as a
    # missing source table -- turning a coding error into an expected absence.
    m = re.search(r'Table with name "?([A-Za-z0-9_]+)"?', message)
    if m:
        return m.group(1)
    # Message in an unexpected shape — caller decides what to do with None.
    return None


def ensure_columns(
    con: duckdb.DuckDBPyConnection,
    schema: str,
    table: str,
    coldefs: dict[str, str],
    *,
    logger: Optional[logging.Logger] = None,
) -> None:
    """Add any missing columns (typed, as NULL) so a coalesce SELECT always binds.

    A coalesce SELECT references source columns inside expressions
    (e.g. ``arr_sql('roles')``, ``coalesce(flag, false)``). ``INSERT ... BY NAME``
    only maps *output* aliases, so every *referenced* source column must
    physically exist or the whole SELECT fails to compile. Two real-data reasons
    a column goes missing:

      * the source never emits it, or
      * dlt drops a column that is all-NULL across the load.

    Pre-creating the union of optionally-referenced columns lets the SELECTs bind
    regardless. Adding a column the SELECT doesn't read is harmless
    (``INSERT ... BY NAME`` ignores it); an already-present column keeps its real
    type (we only add when missing). No-op if the table doesn't exist — the
    following ``safe_execute`` INSERT logs that skip.

    *logger*, if given, is used instead of this module's logger so a collector's
    ``%(name)s`` log field stays under its namespace (log parity).
    """
    log = logger or _LOG
    exists = con.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = ? AND table_name = ?",
        [schema, table],
    ).fetchone()
    if not exists:
        # Missing table is handled (and logged) by the safe_execute INSERT after.
        log.debug("ensure_columns: table %s.%s absent; nothing to do", schema, table)
        return

    have = {
        row[0]
        for row in con.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = ? AND table_name = ?",
            [schema, table],
        ).fetchall()
    }
    for col, sqltype in coldefs.items():
        if col in have:
            # Column already present — leave its real type untouched.
            continue
        # Column referenced by a coalesce SELECT but absent in this load — add as NULL.
        con.execute(f'ALTER TABLE {schema}.{table} ADD COLUMN "{col}" {sqltype}')
        log.debug("ensure_columns: added %s.%s.%s (%s)", schema, table, col, sqltype)


def arr_sql(col: str) -> str:
    """Return SQL that normalizes a list-shaped column to ``VARCHAR[]``, whatever
    physical shape dlt produced.

    The same logical list can arrive in *four* physical shapes; the result is
    always ``VARCHAR[]`` for uniform aggregation:

      * ``NULL``                              -> ``[]``
      * a VARCHAR holding JSON-array TEXT     -> parsed JSON elements
        (e.g. ``'["a","b"]'`` from a collector that stringified a Python list)
      * a plain / comma-joined VARCHAR scalar -> ``string_split(., ',')``
      * a native JSON array or ``VARCHAR[]``  -> ``CAST(. AS VARCHAR[])``

    The JSON branch is gated on a leading ``[`` (after trimming) so only true
    array text takes it; ``TRY_CAST`` + ``coalesce`` mean malformed JSON degrades
    to ``[]`` rather than failing the whole INSERT. DuckDB's ``typeof()`` returns
    ``'VARCHAR'`` for scalars / JSON-text and ``'JSON'`` / ``'VARCHAR[]'`` for the
    native shapes.
    """
    as_varchar = f"CAST({col} AS VARCHAR)"
    return (
        f"CASE "
        f"WHEN {col} IS NULL THEN CAST([] AS VARCHAR[]) "
        # VARCHAR that *contains* JSON-array text: parse it, not comma-split it.
        f"WHEN typeof({col}) = 'VARCHAR' AND ltrim({as_varchar}) LIKE '[%' "
        f"  THEN coalesce(CAST(TRY_CAST({as_varchar} AS JSON) AS VARCHAR[]), CAST([] AS VARCHAR[])) "
        # Plain / comma-joined VARCHAR scalar.
        f"WHEN typeof({col}) = 'VARCHAR' THEN string_split({as_varchar}, ',') "
        # Native JSON array or VARCHAR[] list.
        f"ELSE CAST({col} AS VARCHAR[]) "
        f"END"
    )
