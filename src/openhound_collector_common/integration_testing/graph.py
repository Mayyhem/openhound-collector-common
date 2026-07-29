"""In-memory graph model + loader for OpenGraph node/edge JSON payloads.

Collector-agnostic: any {"graph": {"nodes": [...], "edges": [...]}} payload
(SCCM, MSSQL, or ConfigManBearPig) loads the same way. Accepts a directory of
*.json files or a .zip containing them.
"""
from __future__ import annotations

import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Node:
    id: str
    kinds: list[str] = field(default_factory=list)
    properties: dict = field(default_factory=dict)


@dataclass
class Edge:
    kind: str
    start: str
    end: str
    properties: dict = field(default_factory=dict)


class Graph:
    """Loaded nodes + edges with an id->Node index and a kind filter for edges."""

    def __init__(self, nodes: list[Node], edges: list[Edge]) -> None:
        self.edges = edges
        self._by_id: dict[str, Node] = {}
        deduped: list[Node] = []
        for n in nodes:
            existing = self._by_id.get(n.id)
            if existing is None:
                self._by_id[n.id] = n
                deduped.append(n)
                continue
            # Duplicate id across payloads (e.g. sccm_ + ad_): union kinds and
            # merge properties (existing non-null value wins). Keep one Node.
            for k in n.kinds:
                if k not in existing.kinds:
                    existing.kinds.append(k)
            for key, val in n.properties.items():
                if existing.properties.get(key) in (None, "", [], {}):
                    existing.properties[key] = val
            logger.debug("Graph: merged duplicate node id %r", n.id)
        self.nodes = deduped

    def node(self, node_id: str) -> Node | None:
        return self._by_id.get(node_id)

    def edges_of_kind(self, kind: str) -> list[Edge]:
        return [e for e in self.edges if e.kind == kind]


def _iter_payload_files(path: Path) -> list[tuple[str, str]]:
    """Return (name, text) for each *.json payload in a dir or inside a zip.

    Decodes as utf-8-sig so a UTF-8 BOM is stripped: ConfigManBearPig.ps1 (and other
    PowerShell tools whose zips --compare-to-zip consumes) write JSON with a BOM, which
    plain utf-8 would leave in front of the '{' and break json.loads. utf-8-sig is a
    no-op for BOM-less payloads, so OpenHound's own output is unaffected.
    """
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            return [(name, zf.read(name).decode("utf-8-sig"))
                    for name in sorted(zf.namelist()) if name.lower().endswith(".json")]  # sorted() for parity with the directory branch -> deterministic merge order
    if path.is_dir():
        return [(p.name, p.read_text(encoding="utf-8-sig")) for p in sorted(path.glob("*.json"))]
    raise ValueError(f"load_graph: {path} is neither a .zip nor a directory")


def load_graph(path: str | Path) -> Graph:
    """Load a Graph from a directory of *.json files or a .zip of them."""
    path = Path(path)
    nodes: list[Node] = []
    edges: list[Edge] = []
    files = _iter_payload_files(path)
    logger.info("load_graph: reading %d payload file(s) from %s", len(files), path)
    for name, text in files:
        try:
            graph = (json.loads(text).get("graph") or {})
        except Exception:
            logger.error("load_graph: failed to parse payload %s", name)
            raise
        for raw in graph.get("nodes") or []:
            nodes.append(Node(id=raw["id"], kinds=list(raw.get("kinds") or []),
                              properties=dict(raw.get("properties") or {})))
        for raw in graph.get("edges") or []:
            edges.append(Edge(kind=raw["kind"], start=raw["start"]["value"],
                              end=raw["end"]["value"], properties=dict(raw.get("properties") or {})))
    logger.info("load_graph: %d nodes, %d edges", len(nodes), len(edges))
    return Graph(nodes, edges)
