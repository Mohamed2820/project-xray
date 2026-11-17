"""Command-line interface for Project X-Ray."""
from __future__ import annotations

import argparse
import math
from pathlib import Path

from xray.connectors import LocalFilesystemConnector
from xray.core.engine import XRayEngine
from xray.plugins import PluginRegistry
from xray.report import write_report
from xray.scanner import MAX_FILES, MAX_SCAN_SECONDS, MAX_TOTAL_BYTES, ProjectScanner
from xray.storage.sqlite import SQLiteDataEngine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray",
        description="Safely inspect a software project without executing its code.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run a bounded static project scan.")
    scan.add_argument("path", type=Path)
    scan.add_argument("--output", "-o", type=Path, default=Path("xray-report.json"))
    scan.add_argument(
        "--database", type=Path,
        help="Optional SQLite history database stored outside the scanned project.",
    )
    scan.add_argument(
        "--osv-db", type=Path,
        help="Optional local OSV JSON dataset for exact package/version advisory matching.",
    )
    scan.add_argument(
        "--max-files", type=int, default=MAX_FILES,
        help=f"Maximum number of files to inventory (default: {MAX_FILES}).",
    )
    scan.add_argument(
        "--max-total-mb", type=int, default=MAX_TOTAL_BYTES // (1024 * 1024),
        help="Maximum total file bytes to process in MiB.",
    )
    scan.add_argument(
        "--max-scan-seconds", type=float, default=MAX_SCAN_SECONDS,
        help="Maximum scan wall-clock budget in seconds.",
    )
    scan.add_argument(
        "--load-plugins", action="store_true",
        help="Load only explicitly named trusted plugins; this is not a sandbox.",
    )
    scan.add_argument(
        "--trusted-plugin", action="append", default=[], metavar="ENTRY_POINT",
        help="Exact xray.analyzers entry-point name to trust (repeatable).",
    )
    history = subparsers.add_parser("history", help="List saved scan snapshots.")
    history.add_argument("--database", type=Path, required=True)
    history.add_argument("--limit", type=int, default=20)
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        if args.load_plugins and not args.trusted_plugin:
            parser.error("--load-plugins requires at least one --trusted-plugin name.")
        if args.trusted_plugin and not args.load_plugins:
            parser.error("--trusted-plugin requires --load-plugins.")
        if args.max_total_mb < 1:
            parser.error("--max-total-mb must be positive.")
        invalid_time = not math.isfinite(args.max_scan_seconds)
        if args.max_files < 1 or invalid_time or args.max_scan_seconds <= 0:
            parser.error("--max-files and --max-scan-seconds must be finite positive values.")

        connector = LocalFilesystemConnector(args.path)
        requested_output = args.output.expanduser()
        if requested_output.is_symlink():
            raise ValueError("The report destination must not be a symbolic link.")
        output = requested_output.resolve()
        try:
            output.relative_to(connector.root)
        except ValueError:
            pass
        else:
            raise ValueError("The report output must be stored outside the scanned project.")

        osv_database = args.osv_db.expanduser() if args.osv_db else None
        if osv_database is not None:
            if osv_database.is_symlink():
                raise ValueError("The OSV database must not be a symbolic link.")
            if not osv_database.is_file() or osv_database.stat().st_size > 50 * 1024 * 1024:
                raise ValueError("The OSV database must be a regular file no larger than 50 MiB.")

        registry = PluginRegistry.with_builtins()
        if args.load_plugins:
            loaded = registry.load_entry_points(args.trusted_plugin)
            print(
                f"Loaded explicitly trusted plugin(s): {', '.join(loaded)}. "
                "Plugins run with X-Ray process permissions."
            )
        store = SQLiteDataEngine(args.database) if args.database else None
        scanner = ProjectScanner(
            registry=registry,
            max_files=args.max_files,
            max_total_bytes=args.max_total_mb * 1024 * 1024,
            max_scan_seconds=args.max_scan_seconds,
            osv_database=osv_database,
        )
        engine = XRayEngine(scanner=scanner, data_engine=store)
        report = engine.scan(connector, persist=store is not None)
        write_report(report, output)
        state = "complete" if report.coverage["scan_complete"] else "partial"
        print(
            f"Report written ({state}) to {output} "
            f"({len(report.files)} files, {len(report.nodes)} nodes, "
            f"{len(report.edges)} edges, {len(report.findings)} findings)."
        )
        if report.coverage["scan_limit_reached"]:
            print(
                "Scan stopped at configured limit: "
                f"{report.coverage['scan_limit_reached']}"
            )
        if store is not None:
            changes = report.analyses.get("changes", {})
            print(
                "Change analysis: "
                f"{changes.get('status', 'unknown')} "
                f"(+{len(changes.get('added', []))} "
                f"~{len(changes.get('modified', []))} "
                f"-{len(changes.get('deleted', []))})."
            )
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
