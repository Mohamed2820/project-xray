"""SQLite-backed report history with explicit, versioned schema initialization."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from xray.core.models import ScanReport
from xray.report import report_json

SCHEMA_VERSION = 1


class SQLiteDataEngine:
    """Persist scan snapshots locally; reports contain redacted findings only."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path).expanduser()

    def initialize(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database_path) as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema {version} is newer than supported {SCHEMA_VERSION}."
                )
            if version == 0:
                connection.executescript(
                    """
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
                    """
                )

    def save_report(self, report: ScanReport) -> str:
        self.initialize()
        payload = report_json(report)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """
                INSERT INTO scans (
                    scan_id, root, created_at, schema_version, file_count,
                    node_count, edge_count, finding_count, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.scan_id,
                    report.root,
                    report.created_at,
                    report.schema_version,
                    len(report.files),
                    len(report.nodes),
                    len(report.edges),
                    len(report.findings),
                    payload,
                ),
            )
        return report.scan_id

    def load_report(self, scan_id: str) -> dict[str, Any] | None:
        self.initialize()
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                "SELECT report_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        self.initialize()
        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT scan_id, root, created_at, schema_version, file_count,
                       node_count, edge_count, finding_count
                FROM scans ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        columns = (
            "scan_id", "root", "created_at", "schema_version", "file_count",
            "node_count", "edge_count", "finding_count",
        )
        return [dict(zip(columns, row, strict=True)) for row in rows]
