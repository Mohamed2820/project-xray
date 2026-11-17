from pathlib import Path

from xray.scanner import scan_project


def test_scan_inventories_and_parses_python(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import os\n\ndef greet():\n    print('hi')\n")
    report = scan_project(tmp_path)
    assert any(item["path"] == "app.py" for item in report.files)
    assert any(node.kind == "function" and node.name == "greet" for node in report.nodes)
    assert any(edge.relation == "imports" for edge in report.edges)


def test_scan_skips_excluded_directories(tmp_path: Path) -> None:
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "secret.py").write_text("password='abcdefghijk'")
    report = scan_project(tmp_path)
    assert report.files == []
    assert report.findings == []


def test_scan_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("print('outside')")
    (tmp_path / "link.py").symlink_to(outside)
    report = scan_project(tmp_path)
    assert report.files == []
