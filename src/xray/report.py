"""Stable JSON report serialization with atomic, private output writes."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from xray.core.models import ScanReport


def report_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)


def write_report(report: ScanReport, destination: Path) -> None:
    """Atomically write a report without following a destination symlink."""
    destination = Path(destination).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError("The report destination must not be a symbolic link.")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp",
        dir=destination.parent, text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(report_json(report))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
