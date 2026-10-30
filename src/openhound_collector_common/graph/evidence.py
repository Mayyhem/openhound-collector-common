"""Shared graph evidence fields, with interpretation left to each collector."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..logging import get_logger

logger = get_logger(__name__)


def merge_sources(*source_lists: Iterable[str]) -> list[str]:
    """Keep each observed source once, in first-observed order.

    Empty input means unknown origin. Never replace it with an inferred method
    name. Callers supply source tags; common has no SQL/SCCM-specific vocabulary.
    """
    result = []
    for sources in source_lists:
        if isinstance(sources, str):
            logger.error("Evidence sources must be a list of tags, not one string")
            raise ValueError("Evidence sources must be a list of strings")
        for source in sources:
            if not isinstance(source, str) or not source.strip():
                logger.error("An evidence source tag is not a nonempty string")
                raise ValueError("Evidence source tags must be nonempty strings")
            if source not in result:
                result.append(source)
            # A repeated observation preserves the first source ordering.
    return result


@dataclass
class EvidenceProperties:
    """Optional fields using ConfigManBearPig's existing serialized names.

    Attributes:
        collectionSource: Unique collection-method tags; empty means unknown.
        assumed: True for an approved inference; confirmed records normally omit it.
        assumptionBasis: Plain-English reason, present only for an inference.
    """

    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    assumed: bool | None = field(default=None, kw_only=True)
    assumptionBasis: str | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        self.collectionSource = merge_sources(self.collectionSource)
        if self.assumed is not None and not isinstance(self.assumed, bool):
            logger.error("An evidence assumption flag must be a boolean or unknown")
            raise ValueError("An evidence assumption flag must be a boolean or None")
        if self.assumed is True and not (
            isinstance(self.assumptionBasis, str) and self.assumptionBasis.strip()
        ):
            logger.error(
                "An inferred graph record needs a plain-English assumption basis"
            )
            raise ValueError("An inferred graph record needs an assumption basis")
        if self.assumed is not True and self.assumptionBasis is not None:
            logger.error("An assumption basis cannot describe an unmarked graph record")
            raise ValueError("An assumption basis requires assumed=True")
        # Valid evidence is ordinary model construction; no per-record log needed.
