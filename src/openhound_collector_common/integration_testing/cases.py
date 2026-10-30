"""Typed integration-test cases (collector-agnostic data model)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CountSpec:
    """Expected match count. None fields are unconstrained; combine at_least+at_most for a range."""

    exact: int | None = None
    at_least: int | None = None
    at_most: int | None = None

    def satisfied_by(self, n: int) -> bool:
        if self.exact is not None and n != self.exact:
            return False
        if self.at_least is not None and n < self.at_least:
            return False
        if self.at_most is not None and n > self.at_most:
            return False
        return True


@dataclass
class NodePattern:
    kinds: list[str] | None = None
    properties: dict | None = None


@dataclass
class EdgeCase:
    id: str
    kind: str
    description: str
    source: NodePattern | None = None
    target: NodePattern | None = None
    properties: dict | None = None
    count: CountSpec | None = None
    negative: bool = False
    reason: str | None = None
    # Reference tools can assert endpoint IDs even when they omit native nodes.
    # Existing node/property matching remains the default for other consumers.
    source_id_pattern: str | None = None
    target_id_pattern: str | None = None
    match_name_before_at: bool = False
    properties_must_match_all: bool = False
    exact_property_values: bool = False


@dataclass
class NodeCase:
    id: str
    description: str
    kinds: list[str]
    properties: dict | None = None
    count: CountSpec | None = None
    negative: bool = False
