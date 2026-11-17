"""SQLite-backed scan, runtime, repair, and test history with private permissions."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xray.analyzers.secrets import redact_sensitive_text
from xray.core.models import ScanReport
from xray.report import report_json

SCHEMA_VERSION = 2
DATABASE_FILE_MODE = 0o600
MAX_HISTORY_ITEMS = 100_000


class SQLiteDataEngine:
    """Persist redacted scan snapshots and bounded runtime/repair telemetry."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path).expanduser()

    def _prepare_database_path(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.database_path.is_symlink():
            raise ValueError("The SQLite database path must not be a symbolic link.")
        if self.database_path.exists():
            metadata = self.database_path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("The SQLite database path must be a regular file.")
            if os.name != "nt":
                os.chmod(self.database_path, DATABASE_FILE_MODE)
        else:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
            descriptor = os.open(self.database_path, flags, DATABASE_FILE_MODE)
            os.close(descriptor)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        self._prepare_database_path()
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version == 0:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        root TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        schema_version TEXT NOT NULL,
                        file_count INTEGER NOT NULL,
                        node_count INTEGER NOT NULL,
                        edge_count INTEGER NOT NULL,
                        finding_count INTEGER NOT NULL,
                        report_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_scans_created_at
                    ON scans(created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_scans_root_created_at
                    ON scans(root, created_at DESC);
                    PRAGMA user_version = 1;
                """)
                version = 1
            else:
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scans_root_created_at "
                    "ON scans(root, created_at DESC)"
                )

            if version < 2:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS runtime_sessions (
                        session_id TEXT PRIMARY KEY,
                        root TEXT NOT NULL,
                        script TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        finished_at TEXT NOT NULL,
                        status TEXT NOT NULL,
                        exit_code INTEGER NOT NULL,
                        error_type TEXT,
                        report_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_runtime_root_started
                    ON runtime_sessions(root, started_at DESC);

                    CREATE TABLE IF NOT EXISTS runtime_events (
                        session_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        elapsed_ns INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        event_json TEXT NOT NULL,
                        PRIMARY KEY(session_id, sequence),
                        FOREIGN KEY(session_id)
                            REFERENCES runtime_sessions(session_id)
                            ON DELETE CASCADE
                    );
                    CREATE INDEX IF NOT EXISTS idx_runtime_events_type
                    ON runtime_events(session_id, event_type, sequence);

                    CREATE TABLE IF NOT EXISTS repair_attempts (
                        repair_id TEXT PRIMARY KEY,
                        root TEXT NOT NULL,
                        session_id TEXT,
                        created_at TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        changed_files_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_repairs_root_created
                    ON repair_attempts(root, created_at DESC);

                    CREATE TABLE IF NOT EXISTS test_runs (
                        test_run_id TEXT PRIMARY KEY,
                        root TEXT NOT NULL,
                        repair_id TEXT,
                        session_id TEXT,
                        created_at TEXT NOT NULL,
                        command TEXT NOT NULL,
                        exit_code INTEGER NOT NULL,
                        passed INTEGER NOT NULL,
                        summary TEXT NOT NULL,
                        FOREIGN KEY(repair_id)
                            REFERENCES repair_attempts(repair_id)
                            ON DELETE SET NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_tests_root_created
                    ON test_runs(root, created_at DESC);
                    PRAGMA user_version = 2;
                """)

    @staticmethod
    def _redacted(value: Any, limit: int = 4000) -> str:
        return redact_sensitive_text(str(value))[:limit]

    def save_report(self, report: ScanReport) -> str:
        self.initialize()
        payload = report_json(report)
        with self._connect() as connection:
            connection.execute("""
                INSERT INTO scans (
                    scan_id, root, created_at, schema_version, file_count,
                    node_count, edge_count, finding_count, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.scan_id, report.root, report.created_at, report.schema_version,
                len(report.files), len(report.nodes), len(report.edges),
                len(report.findings), payload,
            ))
        return report.scan_id

    def latest_report(self, root: str) -> dict[str, Any] | None:
        """Return the latest report for the exact normalized project root."""
        if self.database_path.is_symlink():
            raise ValueError("The SQLite database path must not be a symbolic link.")
        if not self.database_path.exists():
            return None
        if not self.database_path.is_file():
            raise ValueError("The SQLite database path must be a regular file.")
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM scans WHERE root = ? "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (root,),
            ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    def load_report(self, scan_id: str) -> dict[str, Any] | None:
        self.initialize()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        self.initialize()
        with self._connect() as connection:
            rows = connection.execute("""
                SELECT scan_id, root, created_at, schema_version, file_count,
                       node_count, edge_count, finding_count
                FROM scans ORDER BY created_at DESC LIMIT ?
            """, (limit,)).fetchall()
        columns = (
            "scan_id", "root", "created_at", "schema_version", "file_count",
            "node_count", "edge_count", "finding_count",
        )
        return [dict(zip(columns, row, strict=True)) for row in rows]

    def save_runtime_session(self, runtime_report: dict[str, Any]) -> str:
        self.initialize()
        session_id = str(runtime_report.get("session_id") or uuid.uuid4().hex)
        root = self._redacted(runtime_report.get("root", ""), 2048)
        script = self._redacted(runtime_report.get("script", ""), 512)
        events = runtime_report.get("events", [])
        if not isinstance(events, list) or len(events) > MAX_HISTORY_ITEMS:
            raise ValueError("Runtime event list exceeds the persistence limit.")
        sanitized_events: list[dict[str, Any]] = []
        for item in events:
            if not isinstance(item, dict):
                continue
            sanitized = dict(item)
            for key in ("detail", "function"):
                if sanitized.get(key) is not None:
                    sanitized[key] = self._redacted(sanitized[key], 1000)
            sanitized_events.append(sanitized)
        stored_report = dict(runtime_report)
        stored_report["events"] = sanitized_events
        timeline = stored_report.get("timeline")
        if isinstance(timeline, dict):
            sanitized_timeline = dict(timeline)
            sanitized_timeline["events"] = sanitized_events
            stored_report["timeline"] = sanitized_timeline
        root_cause = stored_report.get("root_cause")
        if isinstance(root_cause, dict) and root_cause.get("message"):
            sanitized_cause = dict(root_cause)
            sanitized_cause["message"] = self._redacted(
                sanitized_cause["message"], 1000
            )
            stored_report["root_cause"] = sanitized_cause
        payload = json.dumps(stored_report, ensure_ascii=False, sort_keys=True)
        with self._connect() as connection:
            connection.execute("""
                INSERT INTO runtime_sessions (
                    session_id, root, script, started_at, finished_at,
                    status, exit_code, error_type, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                root,
                script,
                self._redacted(runtime_report.get("started_at", ""), 64),
                self._redacted(runtime_report.get("finished_at", ""), 64),
                str(runtime_report.get("status", "unknown"))[:32],
                int(runtime_report.get("exit_code", 1)),
                self._redacted(runtime_report.get("error_type") or "", 128) or None,
                payload,
            ))
            connection.executemany("""
                INSERT INTO runtime_events (
                    session_id, sequence, elapsed_ns, event_type, event_json
                ) VALUES (?, ?, ?, ?, ?)
            """, [
                (
                    session_id,
                    int(event.get("sequence", index)),
                    int(event.get("elapsed_ns", 0)),
                    str(event.get("event_type", "unknown"))[:64],
                    json.dumps(event, ensure_ascii=False, sort_keys=True),
                )
                for index, event in enumerate(sanitized_events, start=1)
            ])
        return session_id

    def record_repair_attempt(
        self,
        root: str | Path,
        summary: str,
        outcome: str,
        *,
        changed_files: list[str] | None = None,
        session_id: str | None = None,
        test_command: str | None = None,
        test_exit_code: int | None = None,
        test_summary: str | None = None,
    ) -> dict[str, str | None]:
        """Record a repair attempt and, optionally, its already-observed test result.

        This method records evidence supplied by the caller; it does not execute
        the repair or test command.
        """
        allowed_outcomes = {"attempted", "applied", "reverted", "failed"}
        if outcome not in allowed_outcomes:
            raise ValueError(f"outcome must be one of: {', '.join(sorted(allowed_outcomes))}")
        if (test_command is None) != (test_exit_code is None):
            raise ValueError("test_command and test_exit_code must be supplied together.")
        if test_summary is not None and test_command is None:
            raise ValueError("test_summary requires a recorded test_command and test_exit_code.")
        if test_exit_code is not None and not -255 <= test_exit_code <= 255:
            raise ValueError("test_exit_code must be between -255 and 255.")
        files = changed_files or []
        if len(files) > 500:
            raise ValueError("A repair attempt may reference at most 500 files.")
        safe_files = [
            self._redacted(item, 512)
            for item in files
            if isinstance(item, str) and item
        ]
        repair_id = uuid.uuid4().hex
        test_run_id: str | None = None
        root_value = self._redacted(root, 2048)
        summary_value = self._redacted(summary, 4000)
        self.initialize()
        with self._connect() as connection:
            connection.execute("""
                INSERT INTO repair_attempts (
                    repair_id, root, session_id, created_at,
                    summary, outcome, changed_files_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                repair_id,
                root_value,
                session_id,
                datetime.now(UTC).isoformat(),
                summary_value,
                outcome,
                json.dumps(safe_files, ensure_ascii=False),
            ))
            if test_command is not None and test_exit_code is not None:
                test_run_id = uuid.uuid4().hex
                connection.execute("""
                    INSERT INTO test_runs (
                        test_run_id, root, repair_id, session_id, created_at,
                        command, exit_code, passed, summary
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    test_run_id,
                    root_value,
                    repair_id,
                    session_id,
                    datetime.now(UTC).isoformat(),
                    self._redacted(test_command, 2000),
                    test_exit_code,
                    int(test_exit_code == 0),
                    self._redacted(test_summary or "", 4000),
                ))
        return {"repair_id": repair_id, "test_run_id": test_run_id}

    def list_runtime_sessions(
        self,
        root: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        self.initialize()
        query = (
            "SELECT session_id, root, script, started_at, finished_at, "
            "status, exit_code, error_type FROM runtime_sessions"
        )
        parameters: tuple[Any, ...] = ()
        if root is not None:
            query += " WHERE root = ?"
            parameters = (str(Path(root).expanduser().resolve()),)
        query += " ORDER BY started_at DESC LIMIT ?"
        parameters += (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        columns = (
            "session_id", "root", "script", "started_at", "finished_at",
            "status", "exit_code", "error_type",
        )
        return [dict(zip(columns, row, strict=True)) for row in rows]

    def list_repair_attempts(
        self,
        root: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        self.initialize()
        query = (
            "SELECT repair_id, root, session_id, created_at, summary, "
            "outcome, changed_files_json FROM repair_attempts"
        )
        parameters: tuple[Any, ...] = ()
        if root is not None:
            query += " WHERE root = ?"
            parameters = (str(Path(root).expanduser().resolve()),)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters += (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        columns = (
            "repair_id", "root", "session_id", "created_at",
            "summary", "outcome", "changed_files_json",
        )
        results = [dict(zip(columns, row, strict=True)) for row in rows]
        for result in results:
            try:
                result["changed_files"] = json.loads(result.pop("changed_files_json"))
            except (json.JSONDecodeError, TypeError):
                result["changed_files"] = []
        return results



    def list_test_runs(
        self,
        root: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        self.initialize()
        query = (
            "SELECT test_run_id, root, repair_id, session_id, created_at, "
            "command, exit_code, passed, summary FROM test_runs"
        )
        parameters: tuple[Any, ...] = ()
        if root is not None:
            query += " WHERE root = ?"
            parameters = (str(Path(root).expanduser().resolve()),)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters += (limit,)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        columns = (
            "test_run_id", "root", "repair_id", "session_id", "created_at",
            "command", "exit_code", "passed", "summary",
        )
        return [dict(zip(columns, row, strict=True)) for row in rows]
