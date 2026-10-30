"""Parse method names once; each collector supplies its own valid choices/rules."""

from dataclasses import dataclass

from ..logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class MethodSelection:
    """Case-insensitive names plus the existing collect-everything shorthand."""

    names: frozenset[str]
    is_all: bool

    def includes(self, name: str) -> bool:
        """Keep phase checks independent of either collector's method vocabulary."""
        return self.is_all or name.casefold() in self.names


def parse_methods(value: str | None) -> MethodSelection:
    """Normalize comma-separated choices without inventing dependency policy.

    Missing/empty text and All retain SCCM's current meaning. Whitespace-only
    text selects nothing. A collector may reject that or unknown names at its
    command boundary; generic parsing does not silently choose another method.
    """
    if value is not None and not isinstance(value, str):
        logger.error("Collection methods must be comma-separated names")
        raise ValueError("Collection methods must be comma-separated names")
    names = frozenset(
        item.strip().casefold() for item in (value or "").split(",") if item.strip()
    )
    return MethodSelection(names, not value or "all" in names)
