"""Preserve run and target ownership while saving collected rows.

These helpers do not decide what a target represents. The collector supplies
non-secret labels and an explicit selection of safe settings. In particular,
never pass an entire authentication/configuration object as saved settings.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, TypeAlias

from ..logging import get_logger

logger = get_logger(__name__)

SavedSetting: TypeAlias = bool | int | float | str | None | list[str]
FORMAT_VERSION = 1


class RowSink(Protocol):
    """The part of a streaming bridge needed to save a collected record."""

    def put(self, table_name: str, row: dict) -> None:
        """Save one row in a registered raw table."""
        ...


def _require_label(value: object, description: str) -> str:
    """Require a nonempty label without logging its potentially sensitive value."""
    if not isinstance(value, str) or not value.strip():
        logger.error("Missing or invalid %s in a saved collection record", description)
        raise ValueError(f"A nonempty {description} is required")
    # Valid labels are ordinary bookkeeping; do not log every row's identifier.
    return value


@dataclass(frozen=True)
class RunDescription:
    """One run's explicit, non-secret settings saved through the raw-table path.

    Attributes:
        run_id: Unique label supplied by the caller for this invocation.
        settings: Explicit safe choices needed to repeat later stages. Supported
            values are scalar JSON values and lists of strings.
    """

    run_id: str
    settings: Mapping[str, SavedSetting]

    def as_row(self) -> dict[str, object]:
        """Return a flat row so DLT cannot create nested settings tables."""
        _require_label(self.run_id, "run identifier")
        for name, value in self.settings.items():
            _require_label(name, "saved setting name")
            if not (
                value is None
                or isinstance(value, (str, bool, int, float))
                or isinstance(value, list)
                and all(isinstance(item, str) for item in value)
            ):
                logger.error("Saved setting has an unsupported value type")
                raise ValueError(
                    "Saved settings must be JSON scalars or lists of strings"
                )
            # Known value shapes need no per-setting log; never print their values.
        return {
            "collection_format_version": FORMAT_VERSION,
            "collection_run_id": self.run_id,
            "settings_json": json.dumps(
                dict(self.settings), sort_keys=True, allow_nan=False
            ),
        }

    @classmethod
    def from_row(cls, row: Mapping[str, object]) -> RunDescription:
        """Validate a loaded run record before later stages trust its settings."""
        if row.get("collection_format_version") != FORMAT_VERSION:
            logger.error(
                "Unsupported saved collection format; collect into a fresh directory"
            )
            raise ValueError(
                "Unsupported saved collection format; recollect into a fresh directory"
            )
        # The supported format is routine; no log is needed for that branch.
        run_id = _require_label(row.get("collection_run_id"), "run identifier")
        encoded = row.get("settings_json")
        if not isinstance(encoded, str):
            logger.error("Saved run settings are missing their JSON text")
            raise ValueError("Saved run settings must contain settings_json")
        # JSON parsing errors must remain visible to the stage caller.
        try:
            settings = json.loads(encoded)
        except (TypeError, ValueError):
            logger.exception("Saved run settings contain invalid JSON")
            raise
        if not isinstance(settings, dict):
            logger.error("Saved run settings must be an object")
            raise ValueError("Saved run settings must be an object")
        # Raw JSON is variable at this one boundary; as_row validates every value.
        description = cls(run_id=run_id, settings=settings)
        description.as_row()
        return description


class TargetRowWriter:
    """Copy rows and attach their owning run/target before handing them to DLT."""

    def __init__(self, sink: RowSink, *, run_id: str, target_id: str) -> None:
        self._sink = sink
        self.run_id = _require_label(run_id, "run identifier")
        self.target_id = _require_label(target_id, "target identifier")

    def put(self, table_name: str, row: Mapping[str, object]) -> None:
        """Save a copied row, rejecting conflicting reserved ownership fields."""
        owned_row = dict(row)
        for name, expected in (
            ("collection_run_id", self.run_id),
            ("collection_target_id", self.target_id),
        ):
            if name in owned_row and owned_row[name] != expected:
                logger.error("Collected row has conflicting reserved field %s", name)
                raise ValueError(f"Collected row has conflicting reserved field {name}")
            # A matching or absent reserved field needs no per-row log.
            owned_row[name] = expected
        self._sink.put(table_name, owned_row)
