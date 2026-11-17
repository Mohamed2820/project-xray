"""Command-line interface."""
from __future__ import annotations

import argparse
from pathlib import Path

from xray.report import write_report
from xray.scanner import scan_project


def main() -> int:
    parser = argparse.ArgumentParser(prog="xray", description="Safely inspect a software project.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run non-executing static inventory and analysis.")
    scan.add_argument("path", type=Path)
    scan.add_argument("--output", "-o", type=Path, default=Path("xray-report.json"))
    args = parser.parse_args()
    if args.command == "scan":
        report = scan_project(args.path)
        write_report(report, args.output)
        print(f"Report written to {args.output} ({len(report.files)} files, "
              f"{len(report.findings)} findings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
