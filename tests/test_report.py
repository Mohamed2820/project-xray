import json
from pathlib import Path

import pytest

from xray.report import write_report
from xray.scanner import scan_project


def test_report_is_valid_json(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text("print('hello')", encoding="utf-8")
    destination = tmp_path / "report.json"
    write_report(scan_project(project), destination)
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.2"
    assert data["coverage"]["code_execution"] is False


def test_report_rejects_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("preserve", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic link"):
        write_report(scan_project(tmp_path), link)
    assert target.read_text(encoding="utf-8") == "preserve"
