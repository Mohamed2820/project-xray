"""Explicit, opt-in Python runtime execution adapter."""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xray.analyzers.safe_io import read_project_text
from xray.runtime.collector import RuntimeCollector

MAX_RUNTIME_SOURCE_BYTES = 5 * 1024 * 1024


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    """Create a new private report file; never overwrite or follow a symlink."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def run_target(
    root: str | Path,
    script: str | Path,
    report_path: str | Path,
    program_args: list[str] | None = None,
    *,
    max_events: int = 10_000,
    max_seconds: float = 120.0,
    timeline_origin_ns: int | None = None,
) -> int:
    """Execute one explicitly selected Python script with bounded event capture.

    This is observation, not sandboxing. The target has the same OS-user
    permissions and inherited environment as the X-Ray process.
    """
    project_root = Path(root).expanduser().resolve(strict=True)
    if not project_root.is_dir():
        raise NotADirectoryError(project_root)
    requested_script = Path(script).expanduser()
    if requested_script.is_symlink():
        raise ValueError("The target script must not be a symbolic link.")
    script_path = (
        requested_script if requested_script.is_absolute()
        else project_root / requested_script
    )
    resolved_script = script_path.resolve(strict=True)
    try:
        relative_script = resolved_script.relative_to(project_root).as_posix()
    except ValueError:
        raise ValueError("The Python script must be inside the project root.") from None
    if resolved_script.suffix.lower() != ".py" or not resolved_script.is_file():
        raise ValueError("The target must be a regular Python .py file.")
    source = read_project_text(
        project_root, relative_script, MAX_RUNTIME_SOURCE_BYTES
    )
    if source is None:
        raise ValueError("The target script is unsafe, unreadable, or exceeds 5 MiB.")

    output_path = Path(report_path)
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError("The runtime report destination already exists.")
    session_id = uuid.uuid4().hex
    started_at = datetime.now(UTC).isoformat()
    collector = RuntimeCollector(
        project_root,
        max_events=max_events,
        max_seconds=max_seconds,
        origin_ns=timeline_origin_ns,
    )
    exit_code = 0
    caught: BaseException | None = None
    try:
        os.chdir(project_root)
        script_parent = str(resolved_script.parent)
        sys.path[:] = [script_parent] + [
            item for item in sys.path if item != script_parent
        ]
        sys.argv = [str(resolved_script), *(program_args or [])]
        namespace = {
            "__name__": "__main__",
            "__file__": str(resolved_script),
            "__package__": None,
            "__cached__": None,
            "__builtins__": __builtins__,
        }
        with collector:
            compiled = compile(source, str(resolved_script), "exec")
            exec(compiled, namespace, namespace)
    except SystemExit as error:
        caught = error
        if error.code is None:
            exit_code = 0
        elif isinstance(error.code, int):
            exit_code = max(0, min(error.code, 255))
        else:
            exit_code = 1
        if exit_code:
            collector.record_exception(error)
    except BaseException as error:
        caught = error
        exit_code = 1
        if not collector.events or collector.events[-1].get("event_type") != "exception":
            collector.record_exception(error)
    finally:
        collector.stop()

    finished_at = datetime.now(UTC).isoformat()
    payload = {
        "schema_version": "1.0",
        "session_id": session_id,
        "root": str(project_root),
        "script": relative_script,
        "started_at": started_at,
        "finished_at": finished_at,
        "exit_code": exit_code,
        "status": "success" if exit_code == 0 else "failed",
        "error_type": type(caught).__name__ if caught is not None else None,
        "events": collector.events,
        "summary": collector.summary(),
        "execution": {
            "explicitly_opted_in": True,
            "sandboxed": False,
            "code_execution": True,
            "network_access_restricted": False,
            "arguments_captured": False,
            "environment_captured": False,
            "stdout_stderr_captured": False,
        },
    }
    _write_private_json(Path(report_path), payload)
    return exit_code


def main() -> int:
    """Private child-process entry point used by the parent CLI."""
    if len(sys.argv) < 7:
        return 2
    root, script, report_path = sys.argv[1:4]
    try:
        max_events = int(sys.argv[4])
        max_seconds = float(sys.argv[5])
        timeline_origin_ns = int(sys.argv[6])
    except (TypeError, ValueError):
        return 2
    args = sys.argv[7:]
    if args and args[0] == "--":
        args = args[1:]
    try:
        return run_target(
            root,
            script,
            report_path,
            args,
            max_events=max_events,
            max_seconds=max_seconds,
            timeline_origin_ns=timeline_origin_ns,
        )
    except BaseException:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
