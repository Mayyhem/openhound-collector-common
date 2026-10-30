"""Write bounded OpenGraph files with caller-selected source labels.

Collectors own graph construction and routing. This module only serializes the
records it receives, publishes complete files, and removes its own older parts.
It deliberately avoids a second DLT pipeline and its persistent load state.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Literal

from dlt.common import json as dlt_json

from ..logging import get_logger
from ..orchestration.resources import ResourceLimitReached, RunResources

logger = get_logger(__name__)
Entity = Literal["nodes", "edges"]
# These are the native kinds emitted by the two current consumers. This is not
# a replacement for BloodHound's full catalog; extend it when a collector needs
# another documented native kind. Base includes SID-only endpoint stubs.
NATIVE_AD_KINDS = frozenset(
    {"Base", "User", "Group", "Computer", "Domain", "Container"}
)


class GraphFileWriter:
    """Stage a file set, then publish it after every supplied record is written.

    ``sources`` maps each filename prefix to its source label, or ``None`` for
    native AD/unlabelled data. The collector chooses the prefix for each record.
    At most ``batch_size`` records or eight MiB of encoded text are buffered per
    prefix/entity pair. A single larger record is written in its own part.

    A write/model failure before publication preserves previous complete files.
    Publication replaces individual files atomically, not an entire directory;
    any publication failure is raised and the run must not report success.
    Only files listed in this writer's validated previous manifest are retired.
    """

    def __init__(
        self,
        output_path: str | Path,
        sources: Mapping[str, str | None],
        *,
        batch_size: int = 1000,
        resources: RunResources | None = None,
    ) -> None:
        if not sources or any(
            not re.fullmatch(r"[a-z][a-z0-9_]*", prefix)
            or (label is not None and (not isinstance(label, str) or not label.strip()))
            for prefix, label in sources.items()
        ):
            logger.error("Graph output needs safe prefixes and nonempty source labels")
            raise ValueError("Invalid graph output prefix or source label")
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or batch_size < 1
        ):
            logger.error("Graph output batch size must be a positive integer")
            raise ValueError("Graph output batch size must be a positive integer")
        self.output_path = Path(output_path)
        self.sources = dict(sources)
        self.batch_size = batch_size
        self.resources = resources
        self.files: list[Path] = []
        self.node_count = 0
        self.edge_count = 0
        self._buffers: dict[tuple[str, Entity], list[str]] = {}
        self._bytes: dict[tuple[str, Entity], int] = {}
        self._parts: dict[tuple[str, Entity], int] = {}
        self._temporary: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> GraphFileWriter:
        if self.resources is not None:
            self.resources.register_path(self.output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(
            prefix=".graph-write-", dir=self.output_path
        )
        logger.debug("Staging graph files for %s", ", ".join(self.sources))
        return self

    def write_node(self, prefix: str, content: Mapping[str, object]) -> None:
        """Write one already-constructed graph node to the selected file set."""
        self._append(prefix, "nodes", content)
        self.node_count += 1

    def write_edge(self, prefix: str, content: Mapping[str, object]) -> None:
        """Write one relationship, preserving its endpoint rules and properties."""
        self._append(prefix, "edges", content)
        self.edge_count += 1

    def _append(
        self, prefix: str, entity: Entity, content: Mapping[str, object]
    ) -> None:
        if self._temporary is None or prefix not in self.sources:
            logger.error(
                "Graph output was used outside its scope or with an unknown prefix"
            )
            raise ValueError("Graph writer is closed or the output prefix is unknown")
        if self.resources is not None:
            self.resources.check()
        record = {name: value for name, value in content.items() if value is not None}
        properties = record.get("properties")
        if isinstance(properties, Mapping):
            # BloodHound properties cannot contain null. Do not sort arrays:
            # only the collector knows whether their order carries meaning.
            record["properties"] = {
                key: value for key, value in properties.items() if value is not None
            }
        # Models may use dates and decimals, which DLT already serializes for
        # both collectors. Retain that conversion at this explicit file boundary.
        encoded = dlt_json.dumps(record)
        size = len(encoded.encode("utf-8"))
        key = (prefix, entity)
        if self._buffers.get(key) and self._bytes[key] + size > 8 * 1024 * 1024:
            logger.debug("Flushing graph part at its encoded byte budget")
            self._flush(key)
        self._buffers.setdefault(key, []).append(encoded)
        self._bytes[key] = self._bytes.get(key, 0) + size
        if len(self._buffers[key]) >= self.batch_size:
            # Reaching a normal batch boundary is routine, not a skipped result.
            self._flush(key)

    def _flush(self, key: tuple[str, Entity]) -> None:
        prefix, entity = key
        self._parts[key] = self._parts.get(key, 0) + 1
        filename = f"{prefix}_{entity}-{self._parts[key]:04d}.json"
        assert self._temporary is not None
        path = Path(self._temporary.name) / filename
        nodes = ",".join(self._buffers.get(key, [])) if entity == "nodes" else ""
        edges = ",".join(self._buffers.get(key, [])) if entity == "edges" else ""
        metadata = (
            ',"metadata":' + json.dumps({"source_kind": self.sources[prefix]})
            if self.sources[prefix] is not None
            else ""
        )
        # All records are encoded before the final document is published.
        path.write_text(
            '{"graph":{"nodes":['
            + nodes
            + '],"edges":['
            + edges
            + "]}"
            + metadata
            + "}\n",
            encoding="utf-8",
        )
        self._buffers[key] = []
        self._bytes[key] = 0
        self.files.append(self.output_path / filename)
        if self.resources is not None:
            # A complete JSON part is the batch boundary. Sampling can stop the
            # next record; it must never truncate this already encoded document.
            self.resources.sample()

    def _previous_files(self, prefix: str) -> set[str]:
        manifest = self.output_path / ".openhound-files" / f"{prefix}.json"
        if not manifest.exists():
            # First output for this prefix has no previous owned parts.
            return set()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        pattern = rf"{re.escape(prefix)}_(nodes|edges)-[0-9]{{4,}}\.json"
        if not isinstance(data, list) or any(
            not isinstance(name, str) or not re.fullmatch(pattern, name)
            for name in data
        ):
            logger.error("Invalid graph file ownership manifest for %s", prefix)
            raise ValueError("Invalid graph file ownership manifest")
        return set(data)

    def _publish(self) -> None:
        assert self._temporary is not None
        # Validate all previous names before replacing or removing any file.
        previous = {prefix: self._previous_files(prefix) for prefix in self.sources}
        for prefix in self.sources:
            for entity in ("nodes", "edges"):
                key: tuple[str, Entity] = (prefix, entity)
                if self._buffers.get(key) or key not in self._parts:
                    # An empty stream still produces an explicit valid document.
                    self._flush(key)
        for file in self.files:
            (Path(self._temporary.name) / file.name).replace(file)
        manifest_directory = self.output_path / ".openhound-files"
        manifest_directory.mkdir(exist_ok=True)
        for prefix, old_names in previous.items():
            pattern = rf"{re.escape(prefix)}_(nodes|edges)-[0-9]{{4,}}\.json"
            names = {
                file.name for file in self.files if re.fullmatch(pattern, file.name)
            }
            for name in old_names - names:
                logger.debug("Removing previous owned graph part %s", name)
                (self.output_path / name).unlink(missing_ok=True)
            manifest = manifest_directory / f"{prefix}.json"
            staged_manifest = Path(self._temporary.name) / f"manifest-{prefix}.json"
            staged_manifest.write_text(json.dumps(sorted(names)), encoding="utf-8")
            staged_manifest.replace(manifest)
        logger.info(
            "Wrote %d graph nodes and %d relationships in %d files",
            self.node_count,
            self.edge_count,
            len(self.files),
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if exc_type is None or isinstance(exc_value, ResourceLimitReached):
                self._publish()
                if self.resources is not None:
                    self.resources.sample()
                    if exc_type is None:
                        self.resources.check()
                # A sampled stop publishes complete current parts, then keeps
                # the original stop exception so callers report partial output.
            else:
                logger.error("Graph generation failed; staged files were not published")
        except ResourceLimitReached:
            logger.warning(
                "Graph generation stopped at a resource limit; complete parts were published"
            )
            raise
        except BaseException:
            logger.exception("Graph file publication failed; conversion is incomplete")
            raise
        finally:
            if self._temporary is not None:
                self._temporary.cleanup()
                self._temporary = None
            # A missing temporary directory means there is nothing owned to close.
