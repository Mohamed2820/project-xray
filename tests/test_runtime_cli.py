import json
from pathlib import Path

from xray.cli import main
from xray.storage.sqlite import SQLiteDataEngine


def test_trace_python_cli_writes_report_and_returns_target_status(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project = tmp_path / "app"
    project.mkdir()
    (project / "main.py").write_text(
        "def greet():\n    print('hello')\n\ngreet()\n",
        encoding="utf-8",
    )
    output = tmp_path / "runtime.json"
    database = tmp_path / "history.sqlite3"
    monkeypatch.setattr(
        "sys.argv",
        [
            "xray", "trace-python",
            "--output", str(output), "--database", str(database),
            "--max-events", "100", "--max-seconds", "10",
            str(project), "main.py",
        ],
    )
    assert main() == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["analyses"]["runtime"]["status"] == "success"
    assert payload["analyses"]["runtime"]["execution"]["sandboxed"] is False
    assert "Runtime report written" in capsys.readouterr().out


def test_record_repair_cli_stores_attempt_and_test_result(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project = tmp_path / "app"
    project.mkdir()
    database = tmp_path / "history.sqlite3"
    monkeypatch.setattr(
        "sys.argv",
        [
            "xray", "record-repair", "--database", str(database),
            "--project", str(project), "--summary", "Fixed regression",
            "--outcome", "applied", "--changed-file", "src/main.py",
            "--test-command", "pytest -q", "--test-exit-code", "0",
            "--test-summary", "12 passed",
        ],
    )
    assert main() == 0
    assert "Repair attempt recorded" in capsys.readouterr().out
    assert len(SQLiteDataEngine(database).list_test_runs()) == 1
