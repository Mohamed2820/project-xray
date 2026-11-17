"""Command-line interface for Project X-Ray."""
from __future__ import annotations

import argparse
import math
from pathlib import Path

from xray.connectors import LocalFilesystemConnector
from xray.core.engine import XRayEngine
from xray.plugins import PluginRegistry
from xray.report import write_report
from xray.runtime.python import PythonRuntimeAdapter
from xray.scanner import MAX_FILES, MAX_SCAN_SECONDS, MAX_TOTAL_BYTES, ProjectScanner
from xray.storage.sqlite import SQLiteDataEngine


def _external_database(path: Path | None, root: Path) -> SQLiteDataEngine | None:
    if path is None:
        return None
    requested = path.expanduser()
    if requested.is_symlink():
        raise ValueError("The history database must not be a symbolic link.")
    resolved = requested.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        return SQLiteDataEngine(resolved)
    raise ValueError("The history database must be stored outside the scanned project.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray",
        description="Inspect projects and optionally observe explicitly launched Python programs.",
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

    trace = subparsers.add_parser(
        "trace-python",
        help="EXPLICITLY EXECUTE one Python script and collect bounded runtime telemetry.",
        description=(
            "Runs the chosen Python script in a child process. This is not a sandbox: "
            "the target inherits the current user's permissions and environment."
        ),
    )
    trace.add_argument("path", type=Path, help="Project root.")
    trace.add_argument("script", type=Path, help="Python .py file inside the project root.")
    trace.add_argument("--output", "-o", type=Path, default=Path("xray-runtime-report.json"))
    trace.add_argument("--database", type=Path, help="Optional external SQLite history database.")
    trace.add_argument("--max-events", type=int, default=10_000)
    trace.add_argument("--max-seconds", type=float, default=120.0)
    trace.add_argument(
        "program_args",
        nargs=argparse.REMAINDER,
        help="Arguments for the target program; place them after --.",
    )

    repair = subparsers.add_parser(
        "record-repair",
        help="Record a repair attempt and its already-observed test result (does not run tests).",
    )
    repair.add_argument("--database", type=Path, required=True)
    repair.add_argument("--project", type=Path, required=True)
    repair.add_argument("--summary", required=True)
    repair.add_argument(
        "--outcome",
        choices=("attempted", "applied", "reverted", "failed"),
        default="attempted",
    )
    repair.add_argument("--changed-file", action="append", default=[])
    repair.add_argument("--session-id")
    repair.add_argument("--test-command")
    repair.add_argument("--test-exit-code", type=int)
    repair.add_argument("--test-summary")

    history = subparsers.add_parser("history", help="List saved static scan snapshots.")
    history.add_argument("--database", type=Path, required=True)
    history.add_argument("--limit", type=int, default=20)

    runtime_history = subparsers.add_parser(
        "runtime-history", help="List saved Python runtime sessions."
    )
    runtime_history.add_argument("--database", type=Path, required=True)
    runtime_history.add_argument("--project", type=Path)
    runtime_history.add_argument("--limit", type=int, default=20)

    repair_history = subparsers.add_parser(
        "repair-history", help="List recorded repair attempts."
    )
    repair_history.add_argument("--database", type=Path, required=True)
    repair_history.add_argument("--project", type=Path)
    repair_history.add_argument("--limit", type=int, default=20)

    test_history = subparsers.add_parser(
        "test-history", help="List recorded test results."
    )
    test_history.add_argument("--database", type=Path, required=True)
    test_history.add_argument("--project", type=Path)
    test_history.add_argument("--limit", type=int, default=20)

    web = subparsers.add_parser("web", help="Open the Arabic read-only HTML dashboard.")
    web.add_argument("--report", type=Path, help="Existing X-Ray JSON report.")
    web.add_argument("--database", type=Path, help="Existing external SQLite history database.")
    web.add_argument("--project", type=Path, help="Project root used to select matching history.")
    web.add_argument("--host", default="127.0.0.1", help="IPv4 loopback address only.")
    web.add_argument("--port", type=int, default=8765, help="Local dashboard port.")
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

        store = _external_database(args.database, connector.root)
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
        scanner = ProjectScanner(
            registry=registry,
            max_files=args.max_files,
            max_total_bytes=args.max_total_mb * 1024 * 1024,
            max_scan_seconds=args.max_scan_seconds,
            osv_database=osv_database,
        )
        report = XRayEngine(
            scanner=scanner,
            data_engine=store,
        ).scan(connector, persist=store is not None)
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

    if args.command == "trace-python":
        if not 1 <= args.max_events <= 100_000:
            parser.error("--max-events must be between 1 and 100000.")
        if not math.isfinite(args.max_seconds) or not 0 < args.max_seconds <= 600:
            parser.error("--max-seconds must be finite and between 0 and 600.")
        connector = LocalFilesystemConnector(args.path)
        store = _external_database(args.database, connector.root)
        requested_output = args.output.expanduser()
        if requested_output.is_symlink():
            raise ValueError("The runtime report destination must not be a symbolic link.")
        try:
            requested_output.resolve().relative_to(connector.root)
        except ValueError:
            pass
        else:
            raise ValueError("The runtime report must be stored outside the scanned project.")
        if store is not None:
            database = store.database_path.resolve()
            try:
                database.relative_to(connector.root)
            except ValueError:
                pass
            else:
                raise ValueError("The history database must be stored outside the scanned project.")

        report = XRayEngine(data_engine=store).scan(connector)
        runtime = PythonRuntimeAdapter().trace(
            report,
            connector.root,
            args.script,
            requested_output,
            args.program_args,
            max_events=args.max_events,
            max_seconds=args.max_seconds,
            database=store,
        )
        if store is not None:
            store.save_report(report)
        print(
            f"Runtime report written to {requested_output} "
            f"(session={runtime['session_id']}, events={len(runtime['events'])}, "
            f"exit_code={runtime['exit_code']})."
        )
        cause = runtime.get("root_cause", {})
        if cause.get("status") == "correlated":
            component = cause.get("root_component") or {}
            print(
                f"Root cause candidate: {component.get('path')}:{component.get('line')} "
                f"(confidence={cause.get('confidence', 0.0):.2f})."
            )
        else:
            print(f"Root cause status: {cause.get('status', 'unknown')}.")
        return 0 if runtime["status"] == "success" else 1

    if args.command == "web":
        if args.report is None and args.database is None:
            parser.error("web requires at least one of --report or --database.")
        from xray.web.server import serve_dashboard

        return serve_dashboard(
            report_path=args.report,
            database_path=args.database,
            project_root=args.project,
            host=args.host,
            port=args.port,
        )

    if args.command == "record-repair":
        connector = LocalFilesystemConnector(args.project)
        store = _external_database(args.database, connector.root)
        assert store is not None
        result = store.record_repair_attempt(
            connector.root,
            args.summary,
            args.outcome,
            changed_files=args.changed_file,
            session_id=args.session_id,
            test_command=args.test_command,
            test_exit_code=args.test_exit_code,
            test_summary=args.test_summary,
        )
        print(f"Repair attempt recorded: {result['repair_id']}")
        if result["test_run_id"]:
            print(f"Test result recorded: {result['test_run_id']}")
        print("No repair or test command was executed by this recording operation.")
        return 0

    if args.command == "history":
        for item in SQLiteDataEngine(args.database).list_scans(args.limit):
            print(
                f"{item['scan_id']}  {item['created_at']}  "
                f"{item['file_count']} files  {item['finding_count']} findings"
            )
        return 0

    if args.command == "runtime-history":
        for item in SQLiteDataEngine(args.database).list_runtime_sessions(
            str(args.project.resolve()) if args.project else None,
            args.limit,
        ):
            print(
                f"{item['session_id']}  {item['started_at']}  "
                f"{item['status']}  exit={item['exit_code']}  {item['script']}"
            )
        return 0

    if args.command == "repair-history":
        for item in SQLiteDataEngine(args.database).list_repair_attempts(
            str(args.project.resolve()) if args.project else None,
            args.limit,
        ):
            print(
                f"{item['repair_id']}  {item['created_at']}  "
                f"{item['outcome']}  {item['summary']}"
            )
        return 0

    if args.command == "test-history":
        for item in SQLiteDataEngine(args.database).list_test_runs(
            str(args.project.resolve()) if args.project else None,
            args.limit,
        ):
            state = "passed" if item["passed"] else "failed"
            print(
                f"{item['test_run_id']}  {item['created_at']}  "
                f"{state} (exit={item['exit_code']})  {item['command']}"
            )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
