from xray.core.models import Node
from xray.runtime.root_cause import analyze_root_cause


def test_root_cause_correlates_traceback_with_static_function() -> None:
    nodes = [
        Node("file:app.py", "file", "app.py", "app.py"),
        Node("function:app.py:1:worker", "function", "worker", "app.py", 1),
        Node("function:app.py:4:main", "function", "main", "app.py", 4),
    ]
    runtime_report = {
        "events": [{
            "event_type": "exception",
            "exception_type": "ValueError",
            "detail": "ValueError: invalid fixture input",
            "path": "app.py",
            "line": 3,
            "function": "worker",
            "stack_trace": [
                {"path": "app.py", "line": 8, "function": "<module>"},
                {"path": "app.py", "line": 6, "function": "main"},
                {"path": "app.py", "line": 3, "function": "worker"},
            ],
        }],
    }
    result = analyze_root_cause(runtime_report, nodes, [])
    assert result["status"] == "correlated"
    assert result["root_component"]["name"] == "worker"
    assert result["confidence"] >= 0.8
    assert result["confidence_level"] == "high"
    assert result["stack_trace"][-1]["function"] == "worker"


def test_root_cause_reports_no_error_without_inventing_one() -> None:
    result = analyze_root_cause({"events": []}, [], [])
    assert result["status"] == "no_unhandled_exception"
    assert result["root_component"] is None
    assert result["confidence"] == 0.0
