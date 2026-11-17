import pytest

from xray.core.models import Edge, Evidence, Node
from xray.graph import ProjectGraph


def test_graph_neighbors_and_transitive_impact() -> None:
    nodes = [
        Node("file:a", "file", "a.py", "a.py"),
        Node("function:a", "function", "run", "a.py", 1),
        Node("call:a", "call", "do_work", "a.py", 2),
        Node("file:b", "file", "b.py", "b.py"),
    ]
    edges = [
        Edge("file:a", "function:a", "contains", Evidence("a.py", 1)),
        Edge("function:a", "call:a", "calls", Evidence("a.py", 2)),
        Edge("file:b", "function:a", "imports", Evidence("b.py", 1)),
    ]
    graph = ProjectGraph(nodes, edges)
    assert graph.neighbors("function:a") == ["call:a", "file:a", "file:b"]
    assert graph.impact("function:a", "upstream") == ["file:a", "file:b"]
    assert graph.impact("file:a", "downstream") == ["call:a", "function:a"]
    assert graph.validate() == []


def test_graph_rejects_invalid_direction() -> None:
    graph = ProjectGraph([Node("n", "file", "n", "n")], [])
    with pytest.raises(ValueError, match="direction"):
        graph.neighbors("n", direction="sideways")
