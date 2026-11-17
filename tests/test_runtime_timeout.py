from pathlib import Path

from xray.core.engine import XRayEngine
from xray.runtime.session import run_python_trace


def test_runtime_timeout_terminates_a_hanging_program(tmp_path: Path) -> None:
    project = tmp_path / "hanging"
    project.mkdir()
    (project / "main.py").write_text(
        "import time\n"
        "def wait_forever():\n"
        "    time.sleep(30)\n"
        "wait_forever()\n",
        encoding="utf-8",
    )
    report = XRayEngine().scan(project)
    runtime = run_python_trace(
        report,
        project,
        "main.py",
        tmp_path / "timeout-report.json",
        max_events=100,
        max_seconds=0.1,
    )
    assert runtime["status"] == "failed"
    assert runtime["process"]["timed_out"] is True
    assert runtime["exit_code"] == 124
    assert any(
        event["event_type"] == "runtime_monitor_error"
        for event in runtime["events"]
    )
