"""Shared target indexes; collectors retain identity and record-merging rules."""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping
from threading import RLock
from types import MappingProxyType
from typing import Generic, TypeVar

from ..logging import get_logger

logger = get_logger(__name__)
Record = TypeVar("Record")


class TargetRegistry(Generic[Record]):
    """Find the same caller-owned record by an identity or one of its names.

    The caller chooses what an identity means and when records should merge.
    Hold lock across a compound find/merge/bind decision so another worker cannot
    create a duplicate in between. Individual index operations also take that
    same reentrant lock. Alias views are read-only; record contents remain owned
    by the collector, such as SCCM site codes or SQL ports and instances.
    """

    def __init__(self, alias_key: Callable[[str], str] = str.lower) -> None:
        self.lock = RLock()
        self._alias_key = alias_key
        self._identities: dict[str, Record] = {}
        self._aliases: dict[str, Record] = {}

    @property
    def aliases(self) -> Mapping[str, Record]:
        """Expose current aliases without allowing unguarded index assignment."""
        return MappingProxyType(self._aliases)

    def find(self, identity: str | None, name: str) -> Record | None:
        """Prefer a caller-proven identity, then fall back to the supplied name."""
        with self.lock:
            if identity is not None:
                record = self._identities.get(identity)
                if record is not None:
                    return record
            return self._aliases.get(self._alias_key(name))

    def bind_identity(self, identity: str, record: Record) -> None:
        """Index an identity after the collector has established that it matches."""
        with self.lock:
            self._identities[identity] = record
            logger.debug("Registered a collection target identity")

    def bind_alias(self, name: str, record: Record) -> None:
        """Keep an old queued name usable when its record gains a better name."""
        with self.lock:
            self._aliases[self._alias_key(name)] = record
            logger.debug("Registered collection target alias %s", name)

    def snapshot(self, identity: Callable[[Record], str]) -> list[Record]:
        """Return each record once using the collector's stable snapshot key."""
        with self.lock:
            return list(
                {identity(record): record for record in self._aliases.values()}.values()
            )


def matches_allowed_targets(
    allowed: Collection[str],
    candidates: Iterable[str],
    normalize: Callable[[str], str] = str.lower,
) -> bool:
    """Match caller-supplied name forms; an empty allow-list allows every target.

    The caller expands its own names and normalizes the allow-list once when
    parsing configuration. This helper never strips a SQL port or instance,
    invents a short hostname, or performs a DNS lookup.
    """
    if not allowed:
        return True  # An absent include-only filter deliberately allows all.
    # The caller normalizes its allow-list once when parsing configuration.
    # Rebuilding a large set for every discovered host would be unnecessary.
    return any(normalize(value) in allowed for value in candidates)
