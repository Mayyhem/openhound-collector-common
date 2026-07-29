# Generalized from sccm/sccm/src/openhound_sccm/models/graph_edge.py and
# models/stub_node.py (SCCM kind specifics removed; the traversable-edge set and
# the AD-principal kind set are now injectable so any collector supplies its own).
"""Generic OpenGraph edge model + edge-endpoint stub-node backfill.

Re-exports the two reusable building blocks:

- :class:`GraphEdge` — turns one "edges" table row into an OpenGraph ``Edge`` of
  any kind, setting ``traversable`` from a collector-supplied allow-list.
- :class:`StubNode` — synthesizes a minimal node for an edge endpoint that has no
  real node row, so the graph has no dangling edge references.
"""

from .graph_edge import GraphEdge, GraphEdgeProperties
from .stub_node import StubNode

__all__ = [
    "GraphEdge",
    "GraphEdgeProperties",
    "StubNode",
]
