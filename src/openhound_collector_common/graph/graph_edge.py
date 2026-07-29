# Generalized from sccm/sccm/src/openhound_sccm/models/graph_edge.py.
#
# "Generalize" per design spec §2.1: the SCCM version hard-imported its own
# SCCMEdgeProperties and the SCCM TRAVERSABLE_EDGE_KINDS allow-list. Here:
#   - a generic GraphEdgeProperties carries the same generic "collection_source"
#     extra alongside the framework's base EdgeProperties fields,
#   - the traversable allow-list is INJECTED per row (the consuming collector
#     decides which of its own edge kinds are traversable) instead of being
#     baked in. A collector typically wraps this model and passes its own set.
"""Generic OpenGraph edge model: one "edges" table row -> one OpenGraph ``Edge``.

A collector's preproc/convert stage produces rows describing directed
relationships (``start_id``, ``end_id``, ``kind``). This model reads those rows
and emits an :class:`~openhound.core.models.entries_dataclass.Edge` of the
matching kind. It never produces a node (``as_node`` returns ``None``) because
these rows are pure edge data; endpoint nodes are produced elsewhere (real node
tables, or :class:`~openhound_collector_common.graph.stub_node.StubNode`).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import ClassVar, Iterator

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict

logger = logging.getLogger(__name__)


@dataclass
class GraphEdgeProperties(EdgeProperties):
    """Generic edge properties: the framework's ``composed``/``traversable`` plus a
    ``collection_source`` provenance list (which collector run(s) produced the edge).
    Collectors that need extra typed edge properties subclass this."""

    collection_source: list[str] = field(default_factory=list, kw_only=True)


class GraphEdge(BaseAsset):
    """One "edges" row -> one OpenGraph ``Edge`` of any kind.

    Endpoints are matched by ``id``. ``traversable`` is decided by membership of
    ``kind`` in the collector-supplied ``traversable_kinds`` allow-list. Never
    produces a node.

    The allow-list is a class attribute defaulting to the empty set, so a
    collector subclasses this model and overrides it::

        class MyEdge(GraphEdge):
            traversable_kinds = {"MyKind_AddMember", "MyKind_Owns"}

    Keeping it a class attribute (rather than a constructor field) means the
    framework can instantiate the model straight from a table row without
    knowing about the allow-list.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    # Collector-agnostic allow-list of traversable edge kinds. Override per
    # collector. Empty by default => every edge is non-traversable unless the
    # subclass opts kinds in. ClassVar so pydantic treats it as a plain class
    # attribute (subclasses can override it) rather than a model field.
    traversable_kinds: ClassVar[frozenset[str]] = frozenset()

    start_id: str | None = None
    end_id: str | None = None
    kind: str | None = None
    collection_source: list[str] | None = None

    @property
    def as_node(self) -> None:
        """Graph edges never produce a node."""
        return None

    @property
    def edges(self) -> Iterator[Edge]:
        """Yield one ``Edge`` for this row.

        A row missing ``start_id``, ``end_id``, or ``kind`` is dropped with a
        warning rather than emitting a malformed edge.
        """
        if not self.start_id or not self.end_id or not self.kind:
            # Incomplete row: nothing safe to emit.
            logger.warning(
                "GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                self.start_id, self.end_id, self.kind,
            )
            return
        # Complete row: emit a single edge, traversability from the allow-list.
        logger.debug(
            "GraphEdge: emitting %s -[%s]-> %s", self.start_id, self.kind, self.end_id,
        )
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=GraphEdgeProperties(
                traversable=self.kind in self.traversable_kinds,
                collection_source=self.collection_source or [],
            ),
        )
