"""Snapshot-based change intelligence; no Git subprocess or source execution."""
from __future__ import annotations

from typing import Any

from xray.core.models import Edge, Evidence, Node
from xray.graph import ProjectGraph


def _nodes(items: list[dict[str, Any]]) -> list[Node]:
    result = []
    for item in items:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        result.append(Node(
            str(item.get("id")), str(item.get("kind", "")),
            str(item.get("name", "")), str(item.get("path", "")),
            item.get("line"), item.get("metadata", {}),
        ))
    return result


def _edges(items: list[dict[str, Any]]) -> list[Edge]:
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
        result.append(Edge(
            str(item.get("source", "")),
            str(item.get("target", "")),
            str(item.get("relation", "")),
            Evidence(
                str(evidence.get("path", "")),
                evidence.get("line"),
                str(evidence.get("detail", "")),
            ),
        ))
    return result


def compare_snapshots(
    current: dict[str, Any],
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare file hashes in two scan reports and estimate structural impact."""
    if previous is None:
        return {
            "status": "baseline_created",
            "previous_scan_id": None,
            "added": [], "modified": [], "deleted": [],
            "unchanged_count": 0,
            "limitations": [
                "This is the initial stored snapshot; a later persisted scan "
                "is needed for comparison.",
                "Changes are based on scanned file hashes, not Git author or commit metadata.",
            ],
        }
    old_files = {
        str(item.get("path")): item
        for item in previous.get("files", [])
        if isinstance(item, dict) and item.get("path")
    }
    new_files = {
        str(item.get("path")): item
        for item in current.get("files", [])
        if isinstance(item, dict) and item.get("path")
    }
    if any(not item.get("sha256") for item in old_files.values()):
        return {
            "status": "previous_snapshot_without_hashes",
            "previous_scan_id": previous.get("scan_id"),
            "added": [], "modified": [], "deleted": [],
            "unchanged_count": 0,
            "limitations": ["The previous snapshot predates per-file SHA-256 tracking."],
        }

    if any(not item.get("sha256") for item in new_files.values()):
        return {
            "status": "current_snapshot_with_missing_hashes",
            "previous_scan_id": previous.get("scan_id"),
            "added": [], "modified": [], "deleted": [],
            "unchanged_count": 0,
            "limitations": [
                "Some current files could not be hashed; "
                "change classification is incomplete."
            ],
        }

    current_graph = ProjectGraph(
        _nodes(current.get("nodes", [])),
        _edges(current.get("edges", [])),
    )
    previous_nodes = _nodes(previous.get("nodes", []))
    old_path_nodes: dict[str, list[Node]] = {}
    for node in previous_nodes:
        old_path_nodes.setdefault(node.path, []).append(node)

    added: list[dict[str, Any]] = []
    modified: list[dict[str, Any]] = []
    deleted: list[dict[str, Any]] = []
    unchanged = 0
    for path, item in new_files.items():
        old = old_files.get(path)
        if old is None:
            change = "added"
        elif old.get("sha256") != item.get("sha256"):
            change = "modified"
        else:
            unchanged += 1
            continue
        node_id = f"file:{path}"
        impact_ids = current_graph.impact(node_id, direction="downstream")
        affected = [
            {
                "id": identifier,
                "kind": current_graph.get_node(identifier).kind,
                "name": current_graph.get_node(identifier).name,
                "path": current_graph.get_node(identifier).path,
            }
            for identifier in impact_ids if current_graph.get_node(identifier) is not None
        ]
        entry = {
            "path": path,
            "change_type": change,
            "previous_sha256": old.get("sha256") if old else None,
            "current_sha256": item.get("sha256"),
            "affected_components": affected,
            "impact_confidence": "structural_graph_only",
        }
        (added if change == "added" else modified).append(entry)

    for path, item in old_files.items():
        if path in new_files:
            continue
        old_components = [
            {
                "id": node.id, "kind": node.kind,
                "name": node.name, "path": node.path,
            }
            for node in old_path_nodes.get(path, [])
            if node.id != f"file:{path}"
        ]
        deleted.append({
            "path": path,
            "change_type": "deleted",
            "previous_sha256": item.get("sha256"),
            "current_sha256": None,
            "affected_components": old_components,
            "impact_confidence": "previous_snapshot_components",
        })

    return {
        "status": "compared",
        "previous_scan_id": previous.get("scan_id"),
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "unchanged_count": unchanged,
        "limitations": [
            "Change history exists only between persisted X-Ray scan snapshots.",
            "No Git author, branch, commit, or rename attribution is inferred.",
            "Affected components are derived from current or previous graph evidence "
            "and are not a complete runtime impact proof.",
        ],
    }
