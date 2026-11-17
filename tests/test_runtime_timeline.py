from xray.runtime.timeline import rebuild_timeline


def test_timeline_orders_events_and_reconstructs_function_spans() -> None:
    result = rebuild_timeline([
        {
            "sequence": 3, "elapsed_ns": 30, "event_type": "function_return",
            "component_id": "f", "thread_id": 1,
        },
        {
            "sequence": 1, "elapsed_ns": 10, "event_type": "function_call",
            "component_id": "f", "thread_id": 1, "path": "app.py",
            "function": "work",
        },
        {
            "sequence": 2, "elapsed_ns": 20, "event_type": "network_event",
        },
        {
            "sequence": 4, "elapsed_ns": 40, "event_type": "function_call",
            "component_id": "g", "thread_id": 1, "path": "app.py",
            "function": "unfinished",
        },
    ])
    assert [event["elapsed_ns"] for event in result["events"]] == [10, 20, 30, 40]
    assert result["event_count"] == 4
    assert result["event_counts"]["network_event"] == 1
    assert result["function_spans"][0]["function"] == "work"
    assert result["function_spans"][0]["duration_ns"] == 20
    assert result["function_spans"][0]["completed"] is True
    assert result["function_spans"][1]["completed"] is False
