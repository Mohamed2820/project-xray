import sqlite3
from pathlib import Path

from xray.storage.sqlite import SQLiteDataEngine


def test_schema_v1_migrates_to_v2_without_losing_scan_rows(tmp_path: Path) -> None:
    database = tmp_path / "old.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE scans (
                scan_id TEXT PRIMARY KEY, root TEXT NOT NULL,
                created_at TEXT NOT NULL, schema_version TEXT NOT NULL,
                file_count INTEGER NOT NULL, node_count INTEGER NOT NULL,
                edge_count INTEGER NOT NULL, finding_count INTEGER NOT NULL,
                report_json TEXT NOT NULL
            );
            INSERT INTO scans VALUES (
                'old-scan', '/fixture', '2026-01-01T00:00:00+00:00',
                '1.2', 1, 1, 0, 0, '{"scan_id":"old-scan"}'
            );
            PRAGMA user_version = 1;
        """)
    store = SQLiteDataEngine(database)
    store.initialize()
    assert store.load_report("old-scan") == {"scan_id": "old-scan"}
    with sqlite3.connect(database) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert version == 2
    assert {"runtime_sessions", "runtime_events", "repair_attempts", "test_runs"} <= tables


def test_repair_attempt_and_test_result_are_redacted_and_queryable(
    tmp_path: Path,
) -> None:
    store = SQLiteDataEngine(tmp_path / "history.sqlite3")
    result = store.record_repair_attempt(
        tmp_path / "project",
        "Fixed token=top-secret-repair-value",
        "applied",
        changed_files=["src/app.py"],
        test_command="pytest -q --token=top-secret-command-value",
        test_exit_code=0,
        test_summary="All tests passed; password=hidden-test-password",
    )
    repairs = store.list_repair_attempts(str(tmp_path / "project"))
    tests = store.list_test_runs(str(tmp_path / "project"))
    assert repairs[0]["repair_id"] == result["repair_id"]
    assert repairs[0]["outcome"] == "applied"
    assert tests[0]["passed"] == 1
    assert tests[0]["exit_code"] == 0
    assert "top-secret-repair-value" not in repr(repairs)
    assert "top-secret-command-value" not in repr(tests)
    assert "hidden-test-password" not in repr(tests)


def test_repair_test_metadata_requires_a_command_and_exit_code(tmp_path: Path) -> None:
    import pytest

    store = SQLiteDataEngine(tmp_path / "history.sqlite3")
    with pytest.raises(ValueError, match="test_command and test_exit_code"):
        store.record_repair_attempt(
            tmp_path / "project",
            "attempt",
            "attempted",
            test_command="pytest",
        )
