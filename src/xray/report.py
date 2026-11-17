"""Stable JSON report serialization."""
import json
from pathlib import Path

from xray.core.models import ScanReport


def report_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)


def write_report(report: ScanReport, destination: Path) -> None:
    destination.write_text(report_json(report) + "\n", encoding="utf-8")
