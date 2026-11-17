"""In-memory directed project graph and impact queries."""
from __future__ import annotations

from collections import deque
from collections.abc import Iterable

from xray.core.models import Edge, Node


class ProjectGraph:
    """Indexed graph for deterministic neighborhood and impact traversal.

    Edges point from the owner/source to the referenced/target node. A file
    contains its functions, while a function calls a call-site node.
    """

    def __init__(self, nodes: Iterable[Node], edges: Iterable[Edge]) -> None:
        self._nodes = {node.id: node for node in nodes}
        self._edges = tuple(edges)
        self._outgoing: dict[str, list[Edge]] = {}
        self._incoming: dict[str, list[Edge]] = {}
        for edge in self._edges:
            self._outgoing.setdefault(edge.source, []).append(edge)
            self._incoming.setdefault(edge.target, []).append(edge)

    @property
    def nodes(self) -> tuple[Node, ...]:
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[Edge, ...]:
        return self._edges

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def neighbors(
        self,
        node_id: str,
        direction: str = "both",
        relations: set[str] | None = None,
    ) -> list[str]:
        if direction not in {"outgoing", "incoming", "both"}:
            raise ValueError("direction must be outgoing, incoming, or both")
        selected: list[Edge] = []
        if direction in {"outgoing", "both"}:
            selected.extend(self._outgoing.get(node_id, ()))
        if direction in {"incoming", "both"}:
            selected.extend(self._incoming.get(node_id, ()))
        neighbors = {
            edge.target if edge.source == node_id else edge.source
            for edge in selected
            if relations is None or edge.relation in relations
        }
        return sorted(neighbors)

    def impact(
        self,
        node_id: str,
        direction: str = "upstream",
        relations: set[str] | None = None,
    ) -> list[str]:
        """Return transitive owners or referenced components.

        Upstream follows incoming edges (owners/dependents); downstream follows
        outgoing edges (components referenced by the node).
        """
        if node_id not in self._nodes:
            return []
        if direction not in {"upstream", "downstream"}:
            raise ValueError("direction must be upstream or downstream")
        queue = deque([node_id])
        visited = {node_id}
        while queue:
            current = queue.popleft()
            edge_map = self._incoming if direction == "upstream" else self._outgoing
            for edge in edge_map.get(current, ()):
                if relations is not None and edge.relation not in relations:
                    continue
                neighbor = edge.source if direction == "upstream" else edge.target
                if neighbor in self._nodes and neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return sorted(visited - {node_id})

    def validate(self) -> list[str]:
        """Return edge IDs with missing endpoints, without mutating the graph."""
        return sorted(
            f"{edge.source}->{edge.target}"
            for edge in self._edges
            if edge.source not in self._nodes or edge.target not in self._nodes
        )


def related_to(node_id: str, nodes: list[Node], edges: list[Edge]) -> list[str]:
    """Backward-compatible direct-neighbor helper."""
    return ProjectGraph(nodes, edges).neighbors(node_id)
