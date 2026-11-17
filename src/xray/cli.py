"""Command-line interface for Project X-Ray."""
from __future__ import annotations

import argparse
from pathlib import Path

from xray.connectors import LocalFilesystemConnector
from xray.core.engine import XRayEngine
from xray.plugins import PluginRegistry
from xray.report import write_report
from xray.scanner import ProjectScanner
from xray.storage.sqlite import SQLiteDataEngine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray",
        description="Safely inspect a software project without executing its code.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run a static project scan.")
    scan.add_argument("path", type=Path)
    scan.add_argument(
        "--output", "-o", type=Path, default=Path("xray-report.json")
    )
    scan.add_argument(
        "--database",
        type=Path,
        help="Optional SQLite history database stored outside the scanned project.",
    )
    scan.add_argument(
        "--load-plugins",
        action="store_true",
        help="Load installed xray.analyzers entry points (trusted plugin code).",
    )
    history = subparsers.add_parser("history", help="List saved scan snapshots.")
    history.add_argument("--database", type=Path, required=True)
    history.add_argument("--limit", type=int, default=20)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if args.command == "scan":
        connector = LocalFilesystemConnector(args.path)
        output = args.output.expanduser().resolve()
        try:
            output.relative_to(connector.root)
        except ValueError:
            pass
        else:
            raise ValueError(
                "The report output must be stored outside the scanned project."
            )

        registry = PluginRegistry.with_builtins()
        if args.load_plugins:
            loaded = registry.load_entry_points()
            print(f"Loaded {len(loaded)} installed analyzer plugin(s).")
        store = SQLiteDataEngine(args.database) if args.database else None
        engine = XRayEngine(
            scanner=ProjectScanner(registry=registry),
            data_engine=store,
        )
        report = engine.scan(connector, persist=store is not None)
        write_report(report, output)
        print(
            f"Report written to {output} "
            f"({len(report.files)} files, {len(report.nodes)} nodes, "
            f"{len(report.edges)} edges, {len(report.findings)} findings)."
        )
        if store is not None:
            print(f"Snapshot saved: {report.scan_id} ({args.database})")
        return 0
    if args.command == "history":
        for item in SQLiteDataEngine(args.database).list_scans(args.limit):
            print(
                f"{item['scan_id']}  {item['created_at']}  "
                f"{item['file_count']} files  {item['finding_count']} findings"
            )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
