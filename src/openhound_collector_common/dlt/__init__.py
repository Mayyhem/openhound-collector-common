# Generalized from sccm/sccm/src/openhound_sccm/transforms.py (the _safe /
# _ensure_columns / _arr helpers only; all SCCM table/transform builders stayed
# in the SCCM extension). These defend DuckDB SQL against dlt dropping absent or
# all-NULL columns (see the dlt column-dropping gotcha in the design spec §14.3).
"""DuckDB-safe SQL helpers shared across OpenHound collectors' preproc stages."""

from .duckdb_safe import arr_sql, ensure_columns, safe_execute

__all__ = [
    "arr_sql",
    "ensure_columns",
    "safe_execute",
]
