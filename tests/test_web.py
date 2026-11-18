from __future__ import annotations

import json
import sqlite3
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from xray.core.engine import XRayEngine
from xray.storage.sqlite import SQLiteDataEngine
from xray.web.server import create_dashboard_server


def _request(server, path: str, method: str = "GET", host_header: str | None = None):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}{path}"
    try:
        request = urllib.request.Request(url, method=method)
        if host_header is not None:
            request.add_header("Host", host_header)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _history_fixture(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    database = tmp_path / "history.sqlite3"
    store = SQLiteDataEngine(database)
    report = XRayEngine(data_engine=store).scan(project, persist=True)
    runtime = {
        "session_id": "session_123",
        "root": str(project.resolve()),
        "script": "main.py",
        "started_at": "2026-11-17T10:00:00+00:00",
        "finished_at": "2026-11-17T10:00:01+00:00",
        "status": "failed",
        "exit_code": 1,
        "error_type": "ValueError",
        "events": [{
            "sequence": 1, "elapsed_ns": 100, "event_type": "exception",
            "exception_type": "ValueError", "detail": "test error",
            "path": "main.py", "line": 2,
        }],
    }
    store.save_runtime_session(runtime)
    return project, database, report


def test_dashboard_serves_arabic_html_and_report_history(tmp_path: Path) -> None:
    project, database, report = _history_fixture(tmp_path)
    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, headers, body = _request(server, "/")
    assert status == 200
    assert "text/html" in headers["Content-Type"]
    html = body.decode("utf-8")
    assert 'lang="ar" dir="rtl"' in html
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "innerHTML" not in html
    assert "eval(" not in html
    assert "<script src=\"https://" not in html
    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, _headers, body = _request(server, "/api/report")
    assert status == 200
    payload = json.loads(body)
    assert payload["scan_id"] == report.scan_id
    assert payload["files"][0]["path"] == "main.py"
    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, _headers, body = _request(server, "/api/history")
    history = json.loads(body)
    assert status == 200
    assert len(history["scans"]) == 1
    assert history["runtimes"][0]["session_id"] == "session_123"


def test_dashboard_runtime_lookup_is_scoped_to_project(tmp_path: Path) -> None:
    project, database, _report = _history_fixture(tmp_path)
    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, _headers, body = _request(server, "/api/runtime/session_123")
    assert status == 200
    assert json.loads(body)["error_type"] == "ValueError"
    other_project = tmp_path / "other"
    other_project.mkdir()
    server = create_dashboard_server(database_path=database, project_root=other_project, port=0)
    status, _headers, _body = _request(server, "/api/runtime/session_123")
    assert status == 404


def test_dashboard_rejects_non_loopback_bind() -> None:
    with pytest.raises(ValueError, match="loopback"):
        create_dashboard_server(host="0.0.0.0", port=0)


def test_dashboard_rejects_report_symlink(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "linked-report.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are not available on this platform.")
    with pytest.raises(ValueError, match="symbolic link"):
        create_dashboard_server(report_path=link, port=0)


def test_dashboard_is_read_only_and_unknown_routes_are_not_found(tmp_path: Path) -> None:
    project, database, _report = _history_fixture(tmp_path)
    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, headers, body = _request(server, "/api/report", method="POST")
    assert status == 405
    assert headers["Allow"] == "GET"
    assert json.loads(body)["error"] == "This dashboard is read-only."
    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, _headers, _body = _request(server, "/../../etc/passwd")
    assert status == 404


def test_dashboard_requires_a_report_or_database() -> None:
    with pytest.raises(ValueError, match="Provide"):
        create_dashboard_server(port=0)



def test_dashboard_rejects_untrusted_host_header(tmp_path: Path) -> None:
    project, database, _report = _history_fixture(tmp_path)
    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, _headers, body = _request(
        server, "/api/report", host_header="attacker.example"
    )
    assert status == 421
    assert json.loads(body)["error"] == "Invalid local dashboard host."


def test_dashboard_does_not_initialize_or_modify_empty_database(tmp_path: Path) -> None:
    database = tmp_path / "empty.sqlite3"
    with sqlite3.connect(database):
        pass
    original_bytes = database.read_bytes()
    server = create_dashboard_server(database_path=database, port=0)
    status, _headers, body = _request(server, "/api/history")
    assert status == 200
    assert json.loads(body) == {
        "scans": [], "runtimes": [], "repairs": [], "tests": []
    }
    assert database.read_bytes() == original_bytes


def test_dashboard_history_text_fields_are_bounded(tmp_path: Path) -> None:
    project, database, _report = _history_fixture(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO repair_attempts VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("repair-large", str(project.resolve()), None, "2026-11-18",
             "S" * 10000, "applied", "[]"),
        )
        connection.execute(
            "INSERT INTO test_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("test-large", str(project.resolve()), None, None, "2026-11-18",
             "C" * 10000, 0, 1, "T" * 10000),
        )

    server = create_dashboard_server(database_path=database, project_root=project, port=0)
    status, _headers, body = _request(server, "/api/history")
    payload = json.loads(body)

    assert status == 200
    assert len(payload["repairs"][0]["summary"]) <= 4000
    assert len(payload["tests"][0]["command"]) <= 2000
    assert len(payload["tests"][0]["summary"]) <= 4000
