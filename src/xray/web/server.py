"""Loopback-only, read-only HTTP dashboard for Project X-Ray."""
from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_REPORT_BYTES = 20 * 1024 * 1024
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
HTML_FILE = Path(__file__).with_name("index.html")


def _validate_file(path: Path | None, label: str,
                   maximum: int | None = None) -> Path | None:
    if path is None:
        return None
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ValueError(f"The {label} path must not be a symbolic link.")
    try:
        metadata = candidate.stat()
    except OSError:
        raise ValueError(f"The {label} file is not accessible.") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"The {label} path must be a regular file.")
    if maximum is not None and metadata.st_size > maximum:
        raise ValueError(f"The {label} file exceeds the configured size limit.")
    return candidate.resolve(strict=True)


def _validate_root(path: Path | None) -> Path | None:
    if path is None:
        return None
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ValueError("The project root must not be a symbolic link.")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise ValueError("The project root is not accessible.") from None
    if not resolved.is_dir():
        raise ValueError("The project root must be a directory.")
    return resolved


def _decode_object(payload: str, maximum: int) -> dict[str, Any] | None:
    if len(payload.encode("utf-8")) > maximum:
        return None
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, RecursionError, TypeError):
        return None
    return value if isinstance(value, dict) else None


class DashboardData:
    """Read scan/runtime history without initializing or modifying its database."""

    def __init__(self, report_path: Path | None, database_path: Path | None,
                 project_root: Path | None) -> None:
        self.report_path = report_path
        self.database_path = database_path
        self.project_root = project_root

    def _connect_readonly(self) -> sqlite3.Connection | None:
        path = self.database_path
        if path is None:
            return None
        if path.is_symlink():
            raise ValueError("The history database must not be a symbolic link.")
        try:
            metadata = path.stat()
        except OSError:
            raise ValueError("The history database is not accessible.") from None
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("The history database must be a regular file.")
        uri = "file:" + quote(str(path.resolve(strict=True)), safe="/:") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    @staticmethod
    def _has_table(connection: sqlite3.Connection, name: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    def _database_report(self) -> dict[str, Any] | None:
        connection = self._connect_readonly()
        if connection is None:
            return None
        try:
            if not self._has_table(connection, "scans"):
                return None
            query = "SELECT report_json FROM scans WHERE length(report_json) <= ?"
            params: tuple[Any, ...] = (MAX_REPORT_BYTES,)
            if self.project_root is not None:
                query += " AND root = ?"
                params += (str(self.project_root),)
            query += " ORDER BY created_at DESC, rowid DESC LIMIT 1"
            row = connection.execute(query, params).fetchone()
            return _decode_object(row["report_json"], MAX_REPORT_BYTES) if row else None
        finally:
            connection.close()

    def report(self) -> dict[str, Any] | None:
        if self.report_path is None:
            return self._database_report()
        path = self.report_path
        if path.is_symlink():
            raise ValueError("The report file must not be a symbolic link.")
        try:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REPORT_BYTES:
                raise ValueError("The report file is not a supported regular file.")
            payload = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise ValueError("The report file could not be read.") from None
        report = _decode_object(payload, MAX_REPORT_BYTES)
        if report is None:
            raise ValueError("The report file does not contain a valid JSON object.")
        if self.project_root is not None and report.get("root"):
            try:
                report_root = Path(str(report["root"])).expanduser().resolve()
            except (OSError, RuntimeError):
                raise ValueError("The report project root is invalid.") from None
            if report_root != self.project_root:
                raise ValueError("The report belongs to a different project root.")
        return report

    def history(self) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {
            "scans": [], "runtimes": [], "repairs": [], "tests": [],
        }
        connection = self._connect_readonly()
        if connection is None:
            return result
        specs = {
            "scans": ("scans", "scan_id, root, created_at, schema_version, file_count, node_count, edge_count, finding_count", "created_at"),
            "runtimes": ("runtime_sessions", "session_id, root, script, started_at, finished_at, status, exit_code, error_type", "started_at"),
            "repairs": ("repair_attempts", "repair_id, root, session_id, created_at, summary, outcome, changed_files_json", "created_at"),
            "tests": ("test_runs", "test_run_id, root, repair_id, session_id, created_at, command, exit_code, passed, summary", "created_at"),
        }
        try:
            for key, (table, columns, order_column) in specs.items():
                if not self._has_table(connection, table):
                    continue
                query = "SELECT " + columns + " FROM " + table
                params: tuple[Any, ...] = ()
                if self.project_root is not None:
                    query += " WHERE root = ?"
                    params = (str(self.project_root),)
                query += " ORDER BY " + order_column + " DESC LIMIT 100"
                result[key] = [dict(row) for row in connection.execute(query, params)]
                if key == "repairs":
                    for item in result[key]:
                        try:
                            item["changed_files"] = json.loads(item.pop("changed_files_json"))
                        except (json.JSONDecodeError, TypeError):
                            item["changed_files"] = []
            return result
        finally:
            connection.close()

    def runtime(self, session_id: str) -> dict[str, Any] | None:
        if not SESSION_ID_PATTERN.fullmatch(session_id):
            return None
        connection = self._connect_readonly()
        if connection is None:
            return None
        try:
            if not self._has_table(connection, "runtime_sessions"):
                return None
            query = (
                "SELECT report_json FROM runtime_sessions "
                "WHERE session_id = ? AND length(report_json) <= ?"
            )
            params: tuple[Any, ...] = (session_id, MAX_RUNTIME_REPORT_BYTES)
            if self.project_root is not None:
                query += " AND root = ?"
                params += (str(self.project_root),)
            row = connection.execute(query, params).fetchone()
            return _decode_object(row["report_json"], MAX_RUNTIME_REPORT_BYTES) if row else None
        finally:
            connection.close()


def create_dashboard_server(*, report_path: Path | None = None,
                            database_path: Path | None = None,
                            project_root: Path | None = None,
                            host: str = "127.0.0.1",
                            port: int = 8765) -> ThreadingHTTPServer:
    """Create a read-only HTTP server restricted to IPv4 loopback."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("The dashboard can bind only to an IPv4 loopback address.") from None
    if address.version != 4 or not address.is_loopback:
        raise ValueError("The dashboard can bind only to an IPv4 loopback address.")
    if report_path is None and database_path is None:
        raise ValueError("Provide --report, --database, or both.")
    if not 0 <= port <= 65535:
        raise ValueError("The port must be between 0 and 65535.")
    source = DashboardData(
        _validate_file(report_path, "report", MAX_REPORT_BYTES),
        _validate_file(database_path, "history database"),
        _validate_root(project_root),
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "ProjectXRayDashboard"
        sys_version = ""

        def log_message(self, _format: str, *args: Any) -> None:
            return

        def end_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'none'",
            )
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            super().end_headers()

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, value: Any) -> None:
            body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def _deny_method(self) -> None:
            body = b'{"error":"This dashboard is read-only."}'
            self.send_response(405)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Allow", "GET")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if len(self.path) > 2048:
                self._json(414, {"error": "Request path too long."})
                return
            path = urlsplit(self.path).path
            try:
                if path == "/":
                    self._send(200, HTML_FILE.read_bytes(), "text/html; charset=utf-8")
                elif path == "/api/health":
                    self._json(200, {
                        "status": "ok",
                        "read_only": True,
                        "database_connected": source.database_path is not None,
                        "report_configured": source.report_path is not None,
                    })
                elif path == "/api/report":
                    value = source.report()
                    if value is None:
                        self._json(404, {"error": "No scan report is available yet."})
                    else:
                        self._json(200, value)
                elif path == "/api/history":
                    self._json(200, source.history())
                elif path.startswith("/api/runtime/"):
                    value = source.runtime(path.removeprefix("/api/runtime/"))
                    if value is None:
                        self._json(404, {"error": "Runtime session not found."})
                    else:
                        self._json(200, value)
                else:
                    self._json(404, {"error": "Not found."})
            except (ValueError, OSError, sqlite3.Error):
                self._json(400, {
                    "error": "Requested dashboard data is unavailable or invalid."
                })

        def do_POST(self) -> None:
            self._deny_method()

        def do_PUT(self) -> None:
            self._deny_method()

        def do_DELETE(self) -> None:
            self._deny_method()

    server_instance = ThreadingHTTPServer((str(address), port), Handler)
    server_instance.daemon_threads = True
    return server_instance


def serve_dashboard(*, report_path: Path | None = None,
                    database_path: Path | None = None,
                    project_root: Path | None = None,
                    host: str = "127.0.0.1",
                    port: int = 8765) -> int:
    """Run the dashboard until interrupted by the user."""
    server = create_dashboard_server(
        report_path=report_path,
        database_path=database_path,
        project_root=project_root,
        host=host,
        port=port,
    )
    print(f"Project X-Ray dashboard: http://{host}:{server.server_port}/")
    print("Read-only mode. Stop with Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
    return 0
