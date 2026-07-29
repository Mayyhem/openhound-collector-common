# Generalized from sccm/sccm/src/openhound_sccm/models/stub_node.py.
#
# "Generalize" per design spec §2.1: the SCCM version imported SCCMNode and
# SCCM's domain_environment_id helper, and hard-coded the AD-principal kind set.
# Here:
#   - a generic concrete Node subclass (GenericNode) supplies the `id` the
#     framework's abstract Node demands, with no UUID derivation,
#   - the AD-principal kind set is a class attribute the consuming collector can
#     override,
#   - the environmentid resolver is a hook method (environment_id_for) the
#     collector can override to do domain-SID extraction; the default just uses
#     the node id, which is correct for non-AD / id-is-environment cases.
"""StubNode: a minimal backfilled node synthesized for an edge endpoint that has
no real node row.

A collector's preproc produces "backfill" rows for edge endpoints that resolved
to an id (a SID, a host id, etc.) not present in any real node table. Each row
carries the endpoint ``id`` and a ``kind`` inferred from the edge kind. This
model turns each row into a bare node so the emitted graph has no dangling edge
references. It emits no edges.
"""
from __future__ import annotations

import logging
from typing import ClassVar

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Node, NodeProperties
from pydantic import ConfigDict

logger = logging.getLogger(__name__)


class GenericNode(Node):
    """Concrete OpenGraph node whose ``id`` is supplied directly (no UUID derivation).

    The framework's :class:`~openhound.core.models.entries_dataclass.Node` is
    abstract and requires each source to provide an ``id``; this minimal concrete
    subclass does exactly that.
    """

    def __init__(self, *, id: str, kinds: list[str], properties: NodeProperties) -> None:
        super().__init__(kinds=kinds, properties=properties)
        self.id = id

    def __post_init__(self):  # pragma: no cover - id is set in __init__
        # id is set by the caller via __init__; nothing to derive here.
        return


class StubNode(BaseAsset):
    """A bare backfilled node (one backfill row): ``id`` + an inferred ``kind``.

    Kinds listed in ``ad_principal_kinds`` additionally get a ``"Base"`` kind
    appended, per the OpenGraph identity model (AD principals are also generic
    "Base" nodes). The set is a class attribute so a collector subclasses this
    and overrides it::

        class MyStubNode(StubNode):
            ad_principal_kinds = {"User", "Group", "Computer"}

    ``environment_id_for`` decides the node's ``environmentid``; the default uses
    the id itself. Collectors that need domain-SID extraction (e.g. mapping
    ``S-1-5-21-X-Y-Z-RID`` -> ``S-1-5-21-X-Y-Z``) override this hook.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    # Collector-agnostic set of kinds that are AD principals (also get "Base").
    # Empty by default; a collector overrides it with its own kind strings.
    # ClassVar so pydantic treats it as a plain (overridable) class attribute
    # rather than a model field.
    ad_principal_kinds: ClassVar[frozenset[str]] = frozenset()

    id: str | None = None
    kind: str | None = None

    def environment_id_for(self, node_id: str) -> str:
        """Resolve the ``environmentid`` for *node_id*.

        Default: the id itself (correct when the id is already the environment
        anchor, or when no domain-SID extraction is wanted). Override in a
        collector subclass for AD domain-SID extraction.
        """
        return node_id

    @property
    def as_node(self) -> GenericNode | None:
        if not self.id or not self.kind:
            # Can't synthesize a node without both id and kind — drop and warn.
            logger.warning(
                "StubNode: dropping row with missing id/kind (id=%r kind=%r)",
                self.id, self.kind,
            )
            return None
        if self.kind in self.ad_principal_kinds:
            # AD principal: append the generic "Base" kind.
            kinds = [self.kind, "Base"]
        else:
            # Non-AD kind: emit the single inferred kind.
            kinds = [self.kind]
        env = self.environment_id_for(self.id)
        logger.debug(
            "StubNode: backfilling node id=%r kinds=%r environmentid=%r",
            self.id, kinds, env,
        )
        return GenericNode(
            id=self.id,
            kinds=kinds,
            properties=NodeProperties(name=self.id, displayname=self.id, environmentid=env),
        )

    @property
    def edges(self):
        """Stub nodes never produce edges."""
        return iter(())
