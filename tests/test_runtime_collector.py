from pathlib import Path

from xray.runtime.collector import RuntimeCollector


def test_collector_records_project_function_calls_without_values(tmp_path: Path) -> None:
    script = tmp_path / "demo.py"
    secret = "do-not-capture-this-argument"
    script.write_text(
        "def worker(secret_value):\n"
        "    return len(secret_value)\n"
        "worker(" + repr(secret) + ")\n",
        encoding="utf-8",
    )
    namespace: dict[str, object] = {}
    collector = RuntimeCollector(tmp_path, max_events=100)
    with collector:
        exec(compile(script.read_text(encoding="utf-8"), str(script), "exec"), namespace)

    calls = [
        item for item in collector.events
        if item["event_type"] == "function_call"
        and item["function"] == "worker"
    ]
    assert len(calls) == 1
    assert calls[0]["path"] == "demo.py"
    assert calls[0]["component_id"].startswith("runtime-function:demo.py:")
    assert secret not in repr(collector.events)
    assert collector.summary()["arguments_captured"] is False
    assert collector.summary()["local_variables_captured"] is False
    assert collector.events[0]["event_type"] == "runtime_started"
    assert collector.events[-1]["event_type"] == "runtime_stopped"


def test_collector_event_limit_is_enforced(tmp_path: Path) -> None:
    collector = RuntimeCollector(tmp_path, max_events=2)
    with collector:
        collector.record("test_event", detail="one")
        collector.record("test_event", detail="two")
    assert len(collector.events) == 2
    assert collector.dropped_events >= 1


def test_collector_restores_existing_profile_hook(tmp_path: Path) -> None:
    previous_profile = __import__("sys").getprofile()
    previous_thread_profile = __import__("threading").getprofile()
    collector = RuntimeCollector(tmp_path)
    with collector:
        assert __import__("sys").getprofile() is not previous_profile
    assert __import__("sys").getprofile() is previous_profile
    assert __import__("threading").getprofile() is previous_thread_profile
