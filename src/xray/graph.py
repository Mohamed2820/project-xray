"""Helpers for graph queries."""
from xray.core.models import Edge, Node


def related_to(node_id: str, nodes: list[Node], edges: list[Edge]) -> list[str]:
    known = {node.id for node in nodes}
    related = {
        edge.target if edge.source == node_id else edge.source
        for edge in edges if edge.source == node_id or edge.target == node_id
    }
    return sorted(related & known)
