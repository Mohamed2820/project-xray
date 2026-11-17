"""Deterministic event chronology and observed function-span reconstruction."""
from __future__ import annotations

from collections import Counter
from typing import Any


def rebuild_timeline(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Order events by monotonic time and pair observed call/return spans."""
    ordered = sorted(
        (dict(item) for item in events if isinstance(item, dict)),
        key=lambda item: (
            int(item.get("elapsed_ns", 0)),
            int(item.get("sequence", 0)),
        ),
    )
    stacks: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    spans: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()

    for event in ordered:
        event_type = str(event.get("event_type", "unknown"))
        counts[event_type] += 1
        component_id = event.get("component_id")
        thread_id = event.get("thread_id")
        key = (thread_id, component_id)
        if event_type == "function_call" and component_id:
            stacks.setdefault(key, []).append(event)
        elif event_type == "function_return" and component_id:
            pending = stacks.get(key, [])
            if pending:
                started = pending.pop()
                start_ns = int(started.get("elapsed_ns", 0))
                end_ns = int(event.get("elapsed_ns", start_ns))
                spans.append({
                    "component_id": component_id,
                    "path": started.get("path"),
                    "function": started.get("function"),
                    "thread_id": thread_id,
                    "start_sequence": started.get("sequence"),
                    "end_sequence": event.get("sequence"),
                    "start_elapsed_ns": start_ns,
                    "end_elapsed_ns": end_ns,
                    "duration_ns": max(0, end_ns - start_ns),
                    "completed": True,
                })

    for (thread_id, component_id), pending in stacks.items():
        for started in pending:
            spans.append({
                "component_id": component_id,
                "path": started.get("path"),
                "function": started.get("function"),
                "thread_id": thread_id,
                "start_sequence": started.get("sequence"),
                "end_sequence": None,
                "start_elapsed_ns": int(started.get("elapsed_ns", 0)),
                "end_elapsed_ns": None,
                "duration_ns": None,
                "completed": False,
            })
    spans.sort(key=lambda item: (
        item["start_elapsed_ns"], item["start_sequence"] or 0
    ))
    return {
        "events": ordered,
        "event_count": len(ordered),
        "event_counts": dict(sorted(counts.items())),
        "function_spans": spans,
        "reconstruction": "monotonic_event_sequence",
        "limitations": [
            "Spans are reconstructed only from observed Python call/return events.",
            "Abrupt termination and unhandled exceptions can leave incomplete spans.",
            "Native, subprocess-internal, and unsupported-language "
            "call stacks are not reconstructed.",
        ],
    }
