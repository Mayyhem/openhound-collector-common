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
