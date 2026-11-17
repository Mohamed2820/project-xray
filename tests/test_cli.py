import json
from pathlib import Path

from xray.cli import main


def test_cli_writes_json_report(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text("print('hello')", encoding="utf-8")
    destination = tmp_path / "report.json"
    monkeypatch.setattr(
        "sys.argv",
        ["xray", "scan", str(project), "--output", str(destination)],
    )

    assert main() == 0
    assert json.loads(destination.read_text(encoding="utf-8"))["files"]
    assert "Report written" in capsys.readouterr().out
