"""SQLite-backed report history with private file permissions and safe defaults."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

from xray.core.models import ScanReport
from xray.report import report_json

SCHEMA_VERSION = 1
DATABASE_FILE_MODE = 0o600


class SQLiteDataEngine:
    """Persist redacted scan snapshots in a user-private local database."""

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
                    PRAGMA user_version = 1;
                """)

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
