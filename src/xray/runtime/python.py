"""Built-in Python runtime adapter."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from xray.core.models import ScanReport
from xray.runtime.base import RuntimeAdapter
from xray.runtime.session import run_python_trace
from xray.storage.sqlite import SQLiteDataEngine


class PythonRuntimeAdapter(RuntimeAdapter):
    """Deep Python tracing using profile hooks and the Python audit framework."""

    language = "python"
    extensions = (".py",)

    def trace(
        self,
        report: ScanReport,
        root: str | Path,
        entrypoint: str | Path,
        output: str | Path,
        program_args: list[str] | None = None,
        **options: Any,
    ) -> dict[str, Any]:
        database = options.pop("database", None)
        if database is not None and not isinstance(database, SQLiteDataEngine):
            raise TypeError("database must be a SQLiteDataEngine or None")
        return run_python_trace(
            report,
            root,
            entrypoint,
            output,
            program_args,
            database=database,
            **options,
        )
