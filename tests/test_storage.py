from pathlib import Path

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
