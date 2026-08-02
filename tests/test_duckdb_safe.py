"""Unit tests for openhound_collector_common.dlt.duckdb_safe."""
import duckdb
import pytest

from openhound_collector_common.dlt.duckdb_safe import (
    arr_sql,
    ensure_columns,
    safe_execute,
)


@pytest.fixture
def con():
    """A fresh in-memory DuckDB connection per test."""
    connection = duckdb.connect(":memory:")
    connection.execute("CREATE SCHEMA s")
    yield connection
    connection.close()


def test_safe_execute_runs_valid_sql(con):
    """safe_execute runs ordinary SQL just like con.execute."""
    con.execute("CREATE TABLE s.t (a INTEGER)")
    safe_execute(con, "insert-one", "INSERT INTO s.t VALUES (1)")
    assert con.execute("SELECT a FROM s.t").fetchone()[0] == 1


def test_safe_execute_swallows_missing_table(con):
    """A missing source table (CatalogException) is swallowed, not raised."""
    # Must not raise even though s.absent does not exist.
    safe_execute(con, "missing", "INSERT INTO s.t SELECT * FROM s.absent")
    # And the connection remains usable afterwards.
    con.execute("CREATE TABLE s.t2 (a INTEGER)")
    assert con.execute("SELECT count(*) FROM s.t2").fetchone()[0] == 0


def test_safe_execute_expected_miss_downgrade(con):
    """The expected_miss hook is consulted with the missing table name."""
    seen = []

    def classifier(_con, missing_name):
        seen.append(missing_name)
        return True  # mark as benign

    safe_execute(
        con,
        "fallback",
        "SELECT * FROM s.wmi_foo",
        expected_miss=classifier,
    )
    # The parsed missing-table name was passed to the classifier.
    assert seen == ["wmi_foo"]


def test_ensure_columns_adds_missing_columns(con):
    """ensure_columns adds typed NULL columns that a later SELECT references."""
    con.execute("CREATE TABLE s.t (a INTEGER)")
    ensure_columns(con, "s", "t", {"roles": "VARCHAR[]", "flag": "BOOLEAN", "a": "INTEGER"})
    cols = {
        row[0]
        for row in con.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='s' AND table_name='t'"
        ).fetchall()
    }
    # The two absent columns were added; the existing one was left alone.
    assert {"a", "roles", "flag"} <= cols


def test_ensure_columns_noop_on_missing_table(con):
    """ensure_columns is a no-op (no raise) when the table doesn't exist."""
    ensure_columns(con, "s", "nope", {"x": "INTEGER"})  # must not raise


def test_ensure_columns_then_safe_select_binds(con):
    """The pair lets a coalesce SELECT that references an absent column compile."""
    con.execute("CREATE TABLE s.src (id INTEGER)")  # note: no 'roles' column
    con.execute("CREATE TABLE s.dst (id INTEGER, roles VARCHAR[])")
    # Without ensure_columns this SELECT can't bind (no s.src.roles).
    ensure_columns(con, "s", "src", {"roles": "VARCHAR[]"})
    con.execute("INSERT INTO s.src (id) VALUES (1)")
    safe_execute(
        con,
        "coalesce-insert",
        f"INSERT INTO s.dst (id, roles) "
        f"SELECT id, {arr_sql('roles')} FROM s.src",
    )
    row = con.execute("SELECT id, roles FROM s.dst").fetchone()
    assert row[0] == 1
    assert row[1] == []  # NULL roles normalized to empty VARCHAR[]


@pytest.mark.parametrize(
    "literal, expected",
    [
        ("CAST(NULL AS VARCHAR)", []),                       # NULL -> []
        ("'[\"a\",\"b\"]'", ["a", "b"]),                     # JSON-array TEXT
        ("'x,y,z'", ["x", "y", "z"]),                        # comma-joined scalar
        ("'solo'", ["solo"]),                                # single scalar
        ("CAST(['p','q'] AS VARCHAR[])", ["p", "q"]),         # native VARCHAR[]
        ("'[bad json'", []),                                  # malformed JSON -> []
    ],
)
def test_arr_sql_normalizes_all_shapes(con, literal, expected):
    """arr_sql turns every physical list shape into VARCHAR[]."""
    result = con.execute(f"SELECT {arr_sql(literal)}").fetchone()[0]
    assert result == expected


# --- con-2ca2: only a MISSING SOURCE TABLE gets the quiet path ---------------
#
# safe_execute exists so a transform whose source table has not been collected yet
# logs and continues -- legitimate, because privilege level decides which tables
# exist. The risk is that the quiet path is wider than that intent: any
# CatalogException whose message merely contains "with name X" was treated as a
# missing source table, so a misspelled function or schema was reported as
# "skipped (missing source)" -- a real coding error dressed as an expected absence.

def test_missing_table_name_parses_a_real_missing_table():
    from openhound_collector_common.dlt.duckdb_safe import duckdb_missing_table_name
    assert duckdb_missing_table_name(
        'Catalog Error: Table with name node_foo does not exist!') == "node_foo"


def test_missing_table_name_rejects_a_missing_function():
    """A missing scalar function is a coding error, not an uncollected source."""
    from openhound_collector_common.dlt.duckdb_safe import duckdb_missing_table_name
    assert duckdb_missing_table_name(
        'Catalog Error: Scalar Function with name list_filtr does not exist!') is None


def test_missing_table_name_rejects_a_missing_schema():
    from openhound_collector_common.dlt.duckdb_safe import duckdb_missing_table_name
    assert duckdb_missing_table_name(
        'Catalog Error: Schema with name nope does not exist!') is None


def test_catalog_error_that_is_not_a_missing_table_is_loud(con, caplog):
    """A misspelled function must be reported as a failure, not a skipped source."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "bad-function", "SELECT list_filtr([1], x -> x > 0)")
    text = caplog.text
    assert "skipped" not in text, text
    assert "bad-function" in text and "failed" in text, text


def test_missing_source_table_is_still_quiet(con, caplog):
    """The intended quiet path is unchanged: logged and swallowed, never raised."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "absent-source", "SELECT * FROM s.never_collected")
    assert "absent-source" in caplog.text, caplog.text
    assert "never_collected" in caplog.text, caplog.text


# --- message shape: one scannable line, detail only when the miss is a surprise ---
#
# DuckDB's CatalogException carries a 'Did you mean "x"?' guess and a re-print of the
# failing SQL with a caret, so logging the whole exception made every skipped transform
# a five-line block -- ~535 lines in one low-privilege SCCM run, all of them expected.

def test_unexpected_miss_is_one_warning_line_plus_a_debug_with_the_detail(con, caplog):
    """The WARNING is scannable; the guess and the SQL echo move to a companion DEBUG."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "node_x<-absent_y", "SELECT * FROM s.absent_y")

    warnings_ = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings_) == 1, [r.getMessage() for r in warnings_]
    summary = warnings_[0].getMessage()
    assert "node_x<-absent_y" in summary
    assert "absent_y" in summary
    assert "\n" not in summary, f"the WARNING must be one line, got:\n{summary}"
    assert "Did you mean" not in summary, summary

    debugs = [r for r in caplog.records
              if r.levelno == logging.DEBUG and "node_x<-absent_y" in r.getMessage()]
    assert debugs, "expected a companion DEBUG carrying the full DuckDB text"
    assert any("Catalog Error" in r.getMessage() for r in debugs), \
        [r.getMessage() for r in debugs]


def test_expected_miss_is_one_debug_line_with_no_companion_detail(con, caplog):
    """An expected absence needs no diagnosis, so it does not get the noisy detail."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "node_x<-absent_y", "SELECT * FROM s.absent_y",
                     expected_miss=lambda _con, _missing: True)

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    relevant = [r for r in caplog.records if "node_x<-absent_y" in r.getMessage()]
    assert len(relevant) == 1, [r.getMessage() for r in relevant]
    assert relevant[0].levelno == logging.DEBUG
    assert "Catalog Error" not in relevant[0].getMessage(), relevant[0].getMessage()


def test_summary_names_the_table_even_when_the_label_does_not(con, caplog):
    """The label is free-form, so the missing table must be named independently."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "some-opaque-label", "SELECT * FROM s.absent_y")
    warnings_ = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings_) == 1
    assert "absent_y" in warnings_[0].getMessage()
