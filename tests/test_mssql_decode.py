"""Tests for the MSSQL row-decode fidelity fixes in ``clients.mssql``.

Two behaviors are pinned here (both are data-fidelity bugs in impacket's
``tds.MSSQL.parseRow`` that the ``_Tds`` subclass corrects):

1. ``tinyint`` (``TDS_INT1TYPE``) decodes to its true integer (0-255), not a
   bool — so ``compatibility_level`` is ``160``, not ``True``.
2. ``bit`` (``TDS_BITTYPE``) decodes to an ``int`` ``0``/``1``, not a bool.

Plus the connection-layer mapping of impacket's literal ``"NULL"`` marker to
Python ``None`` (``_nulls_to_none``).

These run without a live SQL Server: we drive ``_Tds.parseRow`` directly with a
hand-built ``colMeta`` + row token, mirroring how impacket calls it internally.
"""
from __future__ import annotations

from impacket import tds

from openhound_collector_common.clients.mssql import _Tds, _nulls_to_none


def _make_client() -> _Tds:
    """Build a ``_Tds`` without opening a socket (``__init__`` only sets fields)."""
    client = _Tds.__new__(_Tds)  # bypass tds.MSSQL.__init__ (it would connect args)
    client.colMeta = []
    client.rows = []
    return client


def _parse_one(colmeta: list[dict], data: bytes) -> dict:
    """Run the parseRow override over one synthetic row and return the row dict."""
    client = _make_client()
    client.colMeta = colmeta
    # impacket's parseRow treats a single-key token as an empty/EOF row
    # (``if len(token) == 1: return 0``), so give the token a second key.
    client.parseRow({"TokenType": tds.TDS_ROW_TOKEN, "Data": data})
    return client.rows[-1]


def _parse_one_with_len(colmeta: list[dict], data: bytes) -> tuple[dict, int]:
    """Run parseRow over one synthetic row; return (row, consumed_byte_length)."""
    client = _make_client()
    client.colMeta = colmeta
    consumed = client.parseRow({"TokenType": tds.TDS_ROW_TOKEN, "Data": data})
    return client.rows[-1], consumed


def test_tinyint_decodes_to_integer_not_bool():
    """A ``tinyint`` column yields its true 0-255 integer (the 160 case)."""
    colmeta = [{"Name": "compatibility_level", "Type": tds.TDS_INT1TYPE}]
    row = _parse_one(colmeta, bytes([160]))
    assert row["compatibility_level"] == 160
    assert not isinstance(row["compatibility_level"], bool)
    assert isinstance(row["compatibility_level"], int)


def test_tinyint_zero_is_zero_not_false():
    """A ``tinyint`` of 0 stays the integer 0 (was previously ``False``)."""
    colmeta = [{"Name": "t", "Type": tds.TDS_INT1TYPE}]
    row = _parse_one(colmeta, bytes([0]))
    assert row["t"] == 0
    assert not isinstance(row["t"], bool)


def test_bit_decodes_to_int_zero_one():
    """A non-nullable ``bit`` column yields ``0``/``1`` ints, not bools."""
    colmeta = [{"Name": "flag", "Type": tds.TDS_BITTYPE}]
    assert _parse_one(colmeta, bytes([1]))["flag"] == 1
    assert _parse_one(colmeta, bytes([0]))["flag"] == 0
    assert not isinstance(_parse_one(colmeta, bytes([1]))["flag"], bool)


def test_mixed_row_preserves_column_alignment():
    """tinyint mixed with a 4-byte int still aligns subsequent columns."""
    import struct

    colmeta = [
        {"Name": "database_id", "Type": tds.TDS_INT4TYPE},
        {"Name": "compatibility_level", "Type": tds.TDS_INT1TYPE},
        {"Name": "next_int", "Type": tds.TDS_INT4TYPE},
    ]
    data = struct.pack("<l", 5) + bytes([160]) + struct.pack("<l", 99)
    row = _parse_one(colmeta, data)
    assert row == {"database_id": 5, "compatibility_level": 160, "next_int": 99}


def test_parserow_returns_consumed_length_for_multirow_loop():
    """parseRow MUST return the bytes it consumed, not None.

    impacket's ``_parse_reply_tokens`` does ``token["Data"] = token["Data"][:tokenLen]``
    after calling parseRow, so the next token starts at the right offset. If the
    override returns ``None`` the slice becomes ``[:None]`` (the whole buffer) and
    the loop treats every following row + the DONE token as one giant ROW —
    yielding exactly one row per result set. This pins the return value so a
    future re-sync of the verbatim impacket copy can't silently drop it again.
    """
    import struct

    colmeta = [
        {"Name": "database_id", "Type": tds.TDS_INT4TYPE},
        {"Name": "compatibility_level", "Type": tds.TDS_INT1TYPE},
    ]
    # 4 bytes (int4) + 1 byte (tinyint) = 5 bytes consumed, plus trailing bytes
    # that belong to the *next* token and must NOT be swallowed by this row.
    data = struct.pack("<l", 5) + bytes([160]) + b"TRAILING_NEXT_TOKEN_BYTES"
    row, consumed = _parse_one_with_len(colmeta, data)
    assert row == {"database_id": 5, "compatibility_level": 160}
    assert consumed == 5, "parseRow must report only the bytes its columns consumed"


def test_nulls_to_none_maps_marker():
    """``_nulls_to_none`` turns impacket's ``"NULL"`` marker into ``None``."""
    row = {"owner_sid": "NULL", "name": "master", "compatibility_level": 160}
    assert _nulls_to_none(row) == {
        "owner_sid": None,
        "name": "master",
        "compatibility_level": 160,
    }
