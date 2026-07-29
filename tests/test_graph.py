"""Unit tests for openhound_collector_common.graph (GraphEdge + StubNode)."""
from openhound.core.models.entries_dataclass import Edge, EdgePath

from openhound_collector_common.graph import GraphEdge, GraphEdgeProperties, StubNode
from openhound_collector_common.graph.stub_node import GenericNode


def test_graph_edge_serializes_to_edge():
    """A complete GraphEdge row yields one OpenGraph Edge with id-matched endpoints."""
    row = GraphEdge(start_id="A", end_id="B", kind="MyKind_Owns", collection_source=["run1"])
    edges = list(row.edges)
    assert len(edges) == 1
    edge = edges[0]
    assert isinstance(edge, Edge)
    assert edge.kind == "MyKind_Owns"
    assert isinstance(edge.start, EdgePath)
    assert edge.start.match_by == "id" and edge.start.value == "A"
    assert edge.end.match_by == "id" and edge.end.value == "B"
    assert isinstance(edge.properties, GraphEdgeProperties)
    assert edge.properties.collection_source == ["run1"]
    # No node is ever produced for an edge row.
    assert row.as_node is None


def test_graph_edge_traversable_from_injected_allow_list():
    """traversable is set from a subclass-supplied allow-list."""

    class MyEdge(GraphEdge):
        traversable_kinds = frozenset({"MyKind_Owns"})

    traversable = list(MyEdge(start_id="A", end_id="B", kind="MyKind_Owns").edges)[0]
    nontraversable = list(MyEdge(start_id="A", end_id="B", kind="MyKind_Connect").edges)[0]
    assert traversable.properties.traversable is True
    assert nontraversable.properties.traversable is False


def test_graph_edge_default_allow_list_is_empty():
    """With the base class (empty allow-list) every edge is non-traversable."""
    edge = list(GraphEdge(start_id="A", end_id="B", kind="AnyKind").edges)[0]
    assert edge.properties.traversable is False


def test_graph_edge_drops_incomplete_row():
    """A row missing an endpoint or kind yields no edge."""
    assert list(GraphEdge(start_id="A", end_id=None, kind="K").edges) == []
    assert list(GraphEdge(start_id=None, end_id="B", kind="K").edges) == []
    assert list(GraphEdge(start_id="A", end_id="B", kind=None).edges) == []


def test_stub_node_backfills_a_node():
    """StubNode synthesizes a minimal node for an endpoint with no node row."""
    node = StubNode(id="S-1-5-21-1-2-3-1000", kind="Server").as_node
    assert isinstance(node, GenericNode)
    assert node.id == "S-1-5-21-1-2-3-1000"
    assert node.kinds == ["Server"]
    # Default environment_id_for() uses the id itself.
    assert node.properties.environmentid == "S-1-5-21-1-2-3-1000"
    assert node.properties.name == "S-1-5-21-1-2-3-1000"
    # Stub nodes emit no edges.
    assert list(StubNode(id="x", kind="Server").edges) == []


def test_stub_node_appends_base_for_ad_kinds():
    """A kind in the injectable AD set also gets the 'Base' kind appended."""

    class MyStub(StubNode):
        ad_principal_kinds = frozenset({"User", "Group", "Computer"})

    assert MyStub(id="S-1-5-21-1-2-3-500", kind="User").as_node.kinds == ["User", "Base"]
    # A non-AD kind stays single-kind.
    assert MyStub(id="srv1", kind="Server").as_node.kinds == ["Server"]


def test_stub_node_environment_id_hook_override():
    """A subclass can override environment_id_for (e.g. domain-SID extraction)."""

    class DomainStub(StubNode):
        ad_principal_kinds = frozenset({"User"})

        def environment_id_for(self, node_id: str) -> str:
            # Strip the trailing RID off an account SID -> domain SID.
            return node_id.rsplit("-", 1)[0]

    node = DomainStub(id="S-1-5-21-10-20-30-1105", kind="User").as_node
    assert node.properties.environmentid == "S-1-5-21-10-20-30"


def test_stub_node_drops_missing_id_or_kind():
    """A row missing id or kind produces no node."""
    assert StubNode(id=None, kind="Server").as_node is None
    assert StubNode(id="x", kind=None).as_node is None
