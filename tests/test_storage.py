import os
from pathlib import Path

import pytest

from xray.core.engine import XRayEngine
from xray.storage.sqlite import SQLiteDataEngine


def test_engine_persists_and_loads_scan_snapshot(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text(
        "def main():\n    print('ok')\n", encoding="utf-8"
    )
    database = tmp_path / "state" / "xray.sqlite3"
    store = SQLiteDataEngine(database)
    report = XRayEngine(data_engine=store).scan(project, persist=True)
    saved = store.load_report(report.scan_id)
    assert saved is not None
    assert saved["scan_id"] == report.scan_id
    assert saved["root"] == str(project.resolve())
    history = store.list_scans()
    assert len(history) == 1
    assert history[0]["node_count"] == len(report.nodes)


def test_engine_does_not_persist_unless_requested(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    database = tmp_path / "history.sqlite3"
    store = SQLiteDataEngine(database)
    XRayEngine(data_engine=store).scan(project)
    assert not database.exists()


def test_database_permissions_are_private_on_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX file mode semantics do not apply on Windows")
    database = tmp_path / "private" / "history.sqlite3"
    SQLiteDataEngine(database).initialize()
    assert database.stat().st_mode & 0o777 == 0o600


def test_database_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symbolic link"):
        SQLiteDataEngine(link).initialize()



def test_engine_compares_successive_scan_snapshots(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "main.py"
    source.write_text("def first():\n    return 1\n", encoding="utf-8")
    deleted = project / "deleted.py"
    deleted.write_text("def old():\n    return 0\n", encoding="utf-8")
    store = SQLiteDataEngine(tmp_path / "history.sqlite3")
    engine = XRayEngine(data_engine=store)

    first = engine.scan(project, persist=True)
    assert first.analyses["changes"]["status"] == "baseline_created"

    source.write_text("def second():\n    return 2\n", encoding="utf-8")
    deleted.unlink()
    (project / "added.py").write_text("def added():\n    return 3\n", encoding="utf-8")
    second = engine.scan(project, persist=True)

    changes = second.analyses["changes"]
    assert changes["status"] == "compared"
    assert any(item["path"] == "main.py" for item in changes["modified"])
    assert any(item["path"] == "added.py" for item in changes["added"])
    assert any(item["path"] == "deleted.py" for item in changes["deleted"])
