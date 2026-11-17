"""Runtime adapter contract for pluggable language-specific observers."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from xray.core.models import ScanReport


@runtime_checkable
class RuntimeAdapter(Protocol):
    """Contract for a language runtime observer.

    Implementations must document their execution model, event limits, and
    whether the observed program is sandboxed. X-Ray never assumes isolation.
    """

    language: str
    extensions: tuple[str, ...]

    def trace(
        self,
        report: ScanReport,
        root: str | Path,
        entrypoint: str | Path,
        output: str | Path,
        program_args: list[str] | None = None,
        **options: Any,
    ) -> dict[str, Any]: ...
