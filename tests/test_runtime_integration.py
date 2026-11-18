import json
import sqlite3
from pathlib import Path

from xray.core.engine import XRayEngine
from xray.runtime.session import run_python_trace
from xray.storage.sqlite import SQLiteDataEngine


def test_child_runtime_trace_captures_exception_and_correlates_static_code(
    tmp_path: Path,
) -> None:
    project = tmp_path / "fixture-project"
    project.mkdir()
    script = project / "app.py"
    secret = "Bearer runtime-secret-token-123456789"
    script.write_text(
        "def worker():\n"
        "    raise ValueError(" + repr(secret) + ")\n"
        "\n"
        "def main():\n"
        "    worker()\n"
        "\n"
        "main()\n",
        encoding="utf-8",
    )
    database = SQLiteDataEngine(tmp_path / "history.sqlite3")
    report = XRayEngine(data_engine=database).scan(project)
    output = tmp_path / "runtime-report.json"

    runtime = run_python_trace(
        report,
        project,
        "app.py",
        output,
        max_events=500,
        max_seconds=20,
        database=database,
    )

    assert runtime["status"] == "failed"
    assert runtime["exit_code"] == 1
    assert runtime["error_type"] == "ValueError"
    assert runtime["summary"]["arguments_captured"] is False
    assert any(event["event_type"] == "function_call" for event in runtime["events"])
    assert any(event["event_type"] == "exception" for event in runtime["events"])
    assert runtime["root_cause"]["status"] == "correlated"
    assert runtime["root_cause"]["root_component"]["name"] == "worker"
    assert runtime["root_cause"]["confidence"] >= 0.8
    assert any(
        item["name"] == "main"
        for item in runtime["root_cause"]["affected_components"]
    )
    assert runtime["timeline"]["event_count"] == len(runtime["events"])
    assert runtime["timeline"]["function_spans"]
    assert secret not in json.dumps(runtime)
    assert output.exists()
    assert any(node.kind == "runtime_function" for node in report.nodes)
    assert any(edge.relation == "runtime_calls" for edge in report.edges)
    assert report.findings[-1].rule_id == "runtime_unhandled_exception"
    sessions = database.list_runtime_sessions(str(project))
    assert len(sessions) == 1
    assert sessions[0]["exit_code"] == 1
    with sqlite3.connect(database.database_path) as connection:
        saved_json = connection.execute(
            "SELECT report_json FROM runtime_sessions WHERE session_id = ?",
            (runtime["session_id"],),
        ).fetchone()[0]
        event_count = connection.execute(
            "SELECT COUNT(*) FROM runtime_events WHERE session_id = ?",
            (runtime["session_id"],),
        ).fetchone()[0]
    assert secret not in saved_json
    assert event_count == len(runtime["events"])


def test_runtime_execution_is_explicit_and_static_scan_does_not_run_target(
    tmp_path: Path,
) -> None:
    project = tmp_path / "safe-project"
    project.mkdir()
    marker = tmp_path / "must-not-exist.txt"
    script = project / "main.py"
    script.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )

    report = XRayEngine().scan(project)
    assert report.coverage["code_execution"] is False
    assert not marker.exists()
    assert not report.analyses.get("runtime")



def test_runtime_refuses_script_escape_and_report_symlink(tmp_path: Path) -> None:
    import pytest

    project = tmp_path / "safe-project"
    project.mkdir()
    script = project / "main.py"
    script.write_text("print('must not run')\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("raise RuntimeError('outside script executed')\n", encoding="utf-8")
    report = XRayEngine().scan(project)

    with pytest.raises(ValueError, match="inside the project root"):
        run_python_trace(
            report, project, outside, tmp_path / "outside-report.json"
        )

    target = tmp_path / "protected-report.json"
    target.write_text("keep-existing-content", encoding="utf-8")
    symlink = tmp_path / "report-link.json"
    symlink.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic link"):
        run_python_trace(report, project, "main.py", symlink)
    assert target.read_text(encoding="utf-8") == "keep-existing-content"


def test_runtime_child_does_not_inherit_sensitive_environment_variables(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "environment-project"
    project.mkdir()
    marker = tmp_path / "environment-marker.txt"
    monkeypatch.setenv("XRAY_AUDIT_TEST_API_TOKEN", "synthetic-private-value")
    monkeypatch.setenv("XRAY_AUDIT_TEST_PASSWORD", "synthetic-password-value")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "untrusted-pythonpath"))
    script = project / "main.py"
    script.write_text(
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('|' .join(["
        "os.getenv('XRAY_AUDIT_TEST_API_TOKEN', 'missing'), "
        "os.getenv('XRAY_AUDIT_TEST_PASSWORD', 'missing'), "
        "os.getenv('PYTHONPATH', 'missing')]))\n",
        encoding="utf-8",
    )
    report = XRayEngine().scan(project)

    runtime = run_python_trace(
        report, project, "main.py", tmp_path / "environment-report.json",
        max_events=200, max_seconds=10,
    )

    assert runtime["status"] == "success"
    assert marker.read_text(encoding="utf-8") == "missing|missing|missing"
    assert runtime["execution"]["environment_filtered"] is True
    assert runtime["execution"]["sensitive_environment_variables_removed"] >= 2
    assert "synthetic-private-value" not in json.dumps(runtime)
    assert "synthetic-password-value" not in json.dumps(runtime)


def test_runtime_trace_terminates_background_descendants_on_posix(
    tmp_path: Path,
) -> None:
    import os
    import time

    import pytest

    if os.name == "nt":
        pytest.skip("Windows process-tree cleanup requires a Job Object backend.")

    project = tmp_path / "descendant-project"
    project.mkdir()
    started = tmp_path / "descendant-started.txt"
    finished = tmp_path / "descendant-finished.txt"
    script = project / "main.py"
    child_code = (
        "from pathlib import Path; import time; "
        f"Path({str(started)!r}).write_text('started'); "
        "time.sleep(0.6); "
        f"Path({str(finished)!r}).write_text('finished')"
    )
    script.write_text(
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "deadline = time.monotonic() + 2\n"
        f"while not __import__('pathlib').Path({str(started)!r}).exists():\n"
        "    if time.monotonic() > deadline:\n"
        "        raise TimeoutError('descendant did not start')\n"
        "    time.sleep(0.01)\n",
        encoding="utf-8",
    )
    report = XRayEngine().scan(project)

    runtime = run_python_trace(
        report, project, "main.py", tmp_path / "descendant-report.json",
        max_events=300, max_seconds=10,
    )
    time.sleep(0.7)

    assert runtime["status"] == "success"
    assert started.exists()
    assert not finished.exists()


def test_child_report_loader_rejects_symlinks_and_hard_links(tmp_path: Path) -> None:
    import pytest

    from xray.runtime.session import _load_child_report

    target = tmp_path / "target.json"
    target.write_text('{"status":"success"}', encoding="utf-8")
    symlink = tmp_path / "child-report-link.json"
    try:
        symlink.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are not available on this platform.")
    assert _load_child_report(symlink) is None

    hard_link = tmp_path / "child-report-hardlink.json"
    try:
        hard_link.hardlink_to(target)
    except OSError:
        pytest.skip("Hard links are not available on this platform.")
    assert _load_child_report(hard_link) is None
