"""Evidence-backed root-cause and affected-component correlation."""
from __future__ import annotations

from typing import Any

from xray.core.models import Edge, Evidence, Node
from xray.graph import ProjectGraph


def analyze_root_cause(
    runtime_report: dict[str, Any],
    static_nodes: list[Node],
    static_edges: list[Edge],
) -> dict[str, Any]:
    """Correlate the deepest project traceback frame with the static component graph."""
    events = runtime_report.get("events", [])
    errors = [
        item for item in events
        if isinstance(item, dict) and item.get("event_type") == "exception"
    ]
    if not errors:
        return {
            "status": "no_unhandled_exception",
            "root_component": None,
            "confidence": 0.0,
            "confidence_level": "none",
            "affected_components": [],
            "explanation": "No unhandled Python exception was recorded.",
        }

    error = errors[-1]
    stack = error.get("stack_trace", [])
    if not isinstance(stack, list):
        stack = []
    frames = [
        frame for frame in stack
        if isinstance(frame, dict) and isinstance(frame.get("path"), str)
    ]
    if not frames and error.get("path"):
        frames = [{
            "path": error.get("path"),
            "line": error.get("line"),
            "function": error.get("function"),
        }]

    runtime_nodes: dict[str, Node] = {}
    runtime_edges: list[Edge] = []
    first_call_by_id: dict[str, dict[str, Any]] = {}
    for event in events:
        if (
            isinstance(event, dict)
            and event.get("event_type") == "function_call"
            and isinstance(event.get("component_id"), str)
        ):
            first_call_by_id.setdefault(event["component_id"], event)
    for event in events:
        if not isinstance(event, dict) or event.get("event_type") != "function_call":
            continue
        component_id = event.get("component_id")
        if not isinstance(component_id, str):
            continue
        path = str(event.get("path") or "")
        line = event.get("line")
        function = str(event.get("function") or "<unknown>")
        runtime_nodes.setdefault(
            component_id,
            Node(component_id, "runtime_function", function, path, line),
        )
        caller = event.get("caller_component_id")
        if isinstance(caller, str) and caller and caller != component_id:
            caller_event = first_call_by_id.get(caller)
            if caller_event:
                runtime_nodes.setdefault(
                    caller,
                    Node(
                        caller,
                        "runtime_function",
                        str(caller_event.get("function") or "<unknown>"),
                        str(caller_event.get("path") or ""),
                        caller_event.get("line"),
                    ),
                )
                runtime_edges.append(Edge(
                    caller,
                    component_id,
                    "runtime_calls",
                    Evidence(path, line, "Observed Python profiler call event."),
                ))

    static_function_nodes = [node for node in static_nodes if node.kind == "function"]
    static_by_path_name: dict[tuple[str, str], list[Node]] = {}
    for node in static_function_nodes:
        static_by_path_name.setdefault(
            (node.path, node.name.split(".")[-1]), []
        ).append(node)
    for runtime_id, runtime_node in runtime_nodes.items():
        candidates = [
            node for node in static_by_path_name.get(
                (runtime_node.path, runtime_node.name.split(".")[-1]), []
            )
            if node.line is not None
            and runtime_node.line is not None
            and node.line <= runtime_node.line
        ]
        if candidates:
            best = max(candidates, key=lambda item: item.line or 0)
            runtime_edges.append(Edge(
                best.id,
                runtime_id,
                "matches_static_component",
                Evidence(
                    runtime_node.path,
                    runtime_node.line,
                    "Path/function-name correlation; heuristic match.",
                ),
            ))

    chosen = frames[-1] if frames else {}
    chosen_path = str(chosen.get("path") or error.get("path") or "")
    chosen_line = chosen.get("line") or error.get("line")
    chosen_function = str(chosen.get("function") or error.get("function") or "")
    exact_matches = [
        node for node in static_function_nodes
        if node.path == chosen_path
        and node.name.split(".")[-1] == chosen_function.split(".")[-1]
    ]
    nearby_matches = [
        node for node in exact_matches
        if node.line is not None and isinstance(chosen_line, int)
        and node.line <= chosen_line
    ]
    static_match = (
        max(nearby_matches, key=lambda item: item.line or 0)
        if nearby_matches else None
    )
    root_component = None
    if static_match is not None:
        confidence = 0.90 if static_match.line == chosen_line else 0.82
        root_component = {
            "id": static_match.id,
            "kind": static_match.kind,
            "name": static_match.name,
            "path": static_match.path,
            "line": static_match.line,
        }
    elif chosen_path:
        file_node = next(
            (node for node in static_nodes if node.kind == "file" and node.path == chosen_path),
            None,
        )
        confidence = 0.58 if file_node else 0.45
        root_component = {
            "id": file_node.id if file_node else f"file:{chosen_path}",
            "kind": "file",
            "name": chosen_path,
            "path": chosen_path,
            "line": chosen_line,
        }
    else:
        confidence = 0.20

    all_nodes = [*static_nodes, *runtime_nodes.values()]
    all_edges = [*static_edges, *runtime_edges]
    graph = ProjectGraph(all_nodes, all_edges)
    start_candidates = [
        (identifier, node)
        for identifier, node in runtime_nodes.items()
        if node.path == chosen_path
        and node.name.split(".")[-1] == chosen_function.split(".")[-1]
        and isinstance(chosen_line, int)
        and isinstance(node.line, int)
        and node.line <= chosen_line
    ]
    start_id = (
        max(start_candidates, key=lambda item: item[1].line or 0)[0]
        if start_candidates else None
    )
    affected_ids = graph.impact(start_id, direction="upstream") if start_id else []
    affected = []
    for identifier in affected_ids:
        node = graph.get_node(identifier)
        if node is None:
            continue
        if node.kind in {"runtime_function", "function", "file"} and node.path:
            affected.append({
                "id": identifier,
                "kind": node.kind,
                "name": node.name,
                "path": node.path,
                "line": node.line,
            })
    if root_component:
        existing_affected_ids = {
            item.get("id") for item in affected
        }
        if root_component.get("id") not in existing_affected_ids:
            affected.insert(0, root_component)
    confidence_level = (
        "high" if confidence >= 0.8
        else "medium" if confidence >= 0.6
        else "low"
    )
    return {
        "status": "correlated" if root_component else "insufficient_evidence",
        "exception_type": error.get("exception_type", "UnknownError"),
        "message": error.get("detail", ""),
        "root_component": root_component,
        "confidence": confidence,
        "confidence_level": confidence_level,
        "confidence_basis": (
            "Static Python function matched by project-relative path and function name."
            if static_match else
            "Only file-level or runtime traceback evidence was available."
        ),
        "stack_trace": frames,
        "affected_components": affected,
        "runtime_call_edges": sum(
            edge.relation == "runtime_calls" for edge in runtime_edges
        ),
        "limitations": [
            "Root-cause selection is heuristic and is not proof of the original defect.",
            "Only observed Python calls and the captured exception stack are correlated.",
            "Unobserved, asynchronous, native, subprocess, and non-Python frames may be absent.",
        ],
    }
