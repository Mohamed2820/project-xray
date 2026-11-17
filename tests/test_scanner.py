from pathlib import Path

from xray.scanner import scan_project


def test_scan_inventories_and_parses_python(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\n\ndef greet():\n    print('hi')\n", encoding="utf-8"
    )
    report = scan_project(tmp_path)
    assert any(item["path"] == "app.py" for item in report.files)
    assert any(node.kind == "function" and node.name == "greet" for node in report.nodes)
    assert any(edge.relation == "imports" for edge in report.edges)


def test_scan_skips_excluded_directories(tmp_path: Path) -> None:
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "secret.py").write_text("password='abcdefghijk'", encoding="utf-8")
    report = scan_project(tmp_path)
    assert report.files == []
    assert report.findings == []


def test_scan_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("print('outside')", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(outside)
    report = scan_project(tmp_path)
    assert report.files == []


def test_scan_stops_at_file_count_budget(tmp_path: Path) -> None:
    for index in range(4):
        (tmp_path / f"{index}.txt").write_text("small", encoding="utf-8")
    report = scan_project(tmp_path, max_files=2)
    assert len(report.files) == 2
    assert report.coverage["scan_limit_reached"] == "max_files"
    assert report.coverage["scan_complete"] is False


def test_scan_stops_at_total_byte_budget(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("123456", encoding="utf-8")
    (tmp_path / "b.txt").write_text("abcdef", encoding="utf-8")
    report = scan_project(tmp_path, max_total_bytes=8)
    assert len(report.files) == 2
    assert report.files[1]["status"] == "skipped_total_size_limit"
    assert report.coverage["scan_limit_reached"] == "max_total_bytes"


def test_scan_reports_complete_when_within_budgets(tmp_path: Path) -> None:
    (tmp_path / "small.txt").write_text("safe", encoding="utf-8")
    report = scan_project(tmp_path)
    assert report.coverage["scan_complete"] is True
    assert report.coverage["scan_limit_reached"] is None



def test_scanner_adds_sha256_to_file_inventory(tmp_path: Path) -> None:
    import hashlib

    source = tmp_path / "payload.txt"
    content = b"hash me"
    source.write_bytes(content)
    report = scan_project(tmp_path)
    assert report.files[0]["sha256"] == hashlib.sha256(content).hexdigest()
