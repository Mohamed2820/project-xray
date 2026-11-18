"""Parent-process runtime orchestration and static/runtime graph correlation."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import sysconfig
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xray.core.models import Edge, Evidence, Finding, Node, ScanReport
from xray.report import write_report
from xray.runtime.root_cause import analyze_root_cause
from xray.runtime.timeline import rebuild_timeline
from xray.storage.sqlite import SQLiteDataEngine

MAX_RUNTIME_REPORT_BYTES = 20 * 1024 * 1024
BOOTSTRAP = "from xray.runtime.runner import main; raise SystemExit(main())"
_SENSITIVE_ENV_NAME = re.compile(
    r"(?:^|[_-])(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?(?:KEY|TOKEN)|"
    r"ACCESS[_-]?KEY|CREDENTIALS?|AUTHORIZATION|COOKIE|PRIVATE[_-]?KEY|"
    r"DATABASE[_-]?(?:URL|URI|DSN)|CONNECTION[_-]?STRING|DSN)(?:$|[_-])",
    re.IGNORECASE,
)
_UNSAFE_PYTHON_ENV = frozenset({
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
    "PYTHONUSERBASE", "PYTHONBREAKPOINT", "LD_PRELOAD", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
})


def _runtime_environment() -> tuple[dict[str, str], int]:
    """Remove common credential variables and Python/native loader injection knobs."""
    filtered: dict[str, str] = {}
    removed_secrets = 0
    for key, value in os.environ.items():
        normalized = key.upper()
        if normalized in _UNSAFE_PYTHON_ENV:
            continue
        if _SENSITIVE_ENV_NAME.search(key):
            removed_secrets += 1
            continue
        filtered[key] = value
    # setup-python and some relocatable interpreters rely on the configured
    # Python library directory. Never inherit a caller-controlled loader path.
    library_dir = sysconfig.get_config_var("LIBDIR")
    if isinstance(library_dir, str) and Path(library_dir).is_dir():
        loader_key = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
        filtered[loader_key] = library_dir
    filtered["PYTHONDONTWRITEBYTECODE"] = "1"
    filtered["PYTHONNOUSERSITE"] = "1"
    filtered["PYTHONSAFEPATH"] = "1"
    filtered["XRAY_RUNTIME_ENV_FILTERED"] = "1"
    return filtered, removed_secrets


def _validate_output(root: Path, destination: Path) -> Path:
    requested = destination.expanduser()
    if requested.is_symlink():
        raise ValueError("Runtime report destination must not be a symbolic link.")
    resolved = requested.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        return resolved
    raise ValueError("Runtime report must be stored outside the scanned project.")


def _load_child_report(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > MAX_RUNTIME_REPORT_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _timeline_event(
    event_type: str,
    sequence: int,
    started_ns: int,
    *,
    process_id: int,
    detail: str,
    exit_code: int | None = None,
    timestamp_utc: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "sequence": sequence,
        "timestamp_utc": timestamp_utc or datetime.now(UTC).isoformat(),
        "elapsed_ns": max(0, time.monotonic_ns() - started_ns),
        "process_id": process_id,
        "thread_id": None,
        "event_type": event_type,
        "component_id": None,
        "path": None,
        "line": None,
        "function": None,
        "caller_component_id": None,
        "duration_ns": None,
        "detail": detail,
    }
    if exit_code is not None:
        event["exit_code"] = exit_code
    return event


def _attach_runtime_graph(report: ScanReport, events: list[dict[str, Any]]) -> None:
    existing_nodes = {node.id for node in report.nodes}
    static_functions: dict[tuple[str, str], list[Node]] = {}
    for item in report.nodes:
        if item.kind == "function":
            static_functions.setdefault(
                (item.path, item.name.split(".")[-1]), []
            ).append(item)
    runtime_nodes: dict[str, Node] = {}
    runtime_edges: list[Edge] = []
    for event in events:
        if event.get("event_type") != "function_call":
            continue
        identifier = event.get("component_id")
        if not isinstance(identifier, str):
            continue
        path = str(event.get("path") or "")
        function = str(event.get("function") or "<unknown>")
        line = event.get("line")
        runtime_nodes.setdefault(
            identifier,
            Node(
                identifier,
                "runtime_function",
                function,
                path,
                line if isinstance(line, int) else None,
                {"observed": True},
            ),
        )
        caller = event.get("caller_component_id")
        if isinstance(caller, str) and caller and caller != identifier:
            runtime_edges.append(Edge(
                caller,
                identifier,
                "runtime_calls",
                Evidence(path, line if isinstance(line, int) else None,
                         "Observed at runtime by Python profiler."),
            ))
    for identifier, node in runtime_nodes.items():
        if identifier not in existing_nodes:
            report.nodes.append(node)
            existing_nodes.add(identifier)
        candidates = [
            item for item in static_functions.get(
                (node.path, node.name.split(".")[-1]), []
            )
            if item.line is not None
            and node.line is not None
            and item.line <= node.line
        ]
        if candidates:
            matched = max(candidates, key=lambda item: item.line or 0)
            runtime_edges.append(Edge(
                matched.id,
                identifier,
                "matches_static_component",
                Evidence(
                    node.path,
                    node.line,
                    "Runtime/static path and function-name correlation.",
                ),
            ))
    report.edges.extend(runtime_edges)


def run_python_trace(
    report: ScanReport,
    root: str | Path,
    script: str | Path,
    output: str | Path,
    program_args: list[str] | None = None,
    *,
    max_events: int = 10_000,
    max_seconds: float = 120.0,
    database: SQLiteDataEngine | None = None,
) -> dict[str, Any]:
    """Run the explicitly named Python program in a child process and attach telemetry."""
    project_root = Path(root).expanduser()
    if project_root.is_symlink():
        raise ValueError("Runtime project root must not be a symbolic link.")
    project_root = project_root.resolve(strict=True)
    if not project_root.is_dir():
        raise NotADirectoryError(project_root)
    if not 1 <= max_events <= 100_000:
        raise ValueError("max_events must be between 1 and 100000")
    if not 0 < max_seconds <= 600:
        raise ValueError("max_seconds must be greater than 0 and at most 600")
    destination = _validate_output(project_root, Path(output))
    script_path = Path(script).expanduser()
    if script_path.is_symlink():
        raise ValueError("The target script must not be a symbolic link.")
    if not script_path.is_absolute():
        script_path = project_root / script_path
    resolved_script = script_path.resolve(strict=True)
    try:
        resolved_script.relative_to(project_root)
    except ValueError:
        raise ValueError("The Python script must be inside the project root.") from None
    if not resolved_script.is_file() or resolved_script.suffix.lower() != ".py":
        raise ValueError("The target must be a regular Python .py file.")

    started_ns = time.monotonic_ns()
    parent_started = datetime.now(UTC).isoformat()
    process: subprocess.Popen[bytes] | None = None
    timed_out = False
    execution_error: str | None = None
    child_report: dict[str, Any] | None = None
    with tempfile.TemporaryDirectory(prefix="xray-runtime-") as temporary:
        child_report_path = Path(temporary) / "child-runtime.json"
        command = [
            sys.executable,
            "-P",
            "-c",
            BOOTSTRAP,
            str(project_root),
            str(resolved_script),
            str(child_report_path),
            str(max_events),
            str(max_seconds),
            str(started_ns),
            "--",
            *(program_args or []),
        ]
        try:
            process_options: dict[str, Any] = {
                "cwd": project_root,
                "stdin": subprocess.DEVNULL,
                "shell": False,
            }
            if os.name == "nt":
                process_options["creationflags"] = getattr(
                    subprocess, "CREATE_NEW_PROCESS_GROUP", 0
                )
            else:
                process_options["start_new_session"] = True
            runtime_env, removed_sensitive_environment_variables = _runtime_environment()
            process_options["env"] = runtime_env
            process = subprocess.Popen(command, **process_options)
            process_id = process.pid
            try:
                exit_code = process.wait(timeout=max_seconds + 2.0)
            except subprocess.TimeoutExpired:
                timed_out = True
                if os.name == "nt":
                    process.kill()
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                exit_code = 124
                execution_error = "Runtime process exceeded its time limit and was terminated."
        except OSError as error:
            process_id = os.getpid()
            exit_code = 127
            execution_error = f"Could not start the Python runtime process: {type(error).__name__}."
        child_report = _load_child_report(child_report_path)

    process_id = process.pid if process is not None else os.getpid()
    events: list[dict[str, Any]] = [
        _timeline_event(
            "process_started", 0, started_ns,
            process_id=process_id,
            detail="Explicit Python child process started; command arguments omitted.",
            timestamp_utc=parent_started,
        )
    ]
    if child_report is not None:
        child_events = child_report.get("events", [])
        if isinstance(child_events, list):
            events.extend(item for item in child_events if isinstance(item, dict))
        exit_code = int(child_report.get("exit_code", exit_code))
    elif execution_error is None:
        execution_error = (
            "Runtime child did not produce a valid report; it may have terminated "
            "abruptly or exceeded the report size limit."
        )
    if execution_error:
        events.append(_timeline_event(
            "runtime_monitor_error",
            len(events),
            started_ns,
            process_id=process_id,
            detail=execution_error,
        ))
    events.append(_timeline_event(
        "process_exited", len(events), started_ns,
        process_id=process_id,
        detail="Python child process exited.",
        exit_code=exit_code,
    ))
    events.sort(key=lambda item: int(item.get("elapsed_ns", 0)))
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence

    runtime_report: dict[str, Any] = {
        "schema_version": "1.0",
        "session_id": (
            child_report.get("session_id") if child_report
            else uuid.uuid4().hex
        ),
        "root": str(project_root),
        "script": resolved_script.relative_to(project_root).as_posix(),
        "started_at": parent_started,
        "runtime_started_at": (
            child_report.get("started_at") if child_report else None
        ),
        "finished_at": datetime.now(UTC).isoformat(),
        "exit_code": exit_code,
        "status": "success" if exit_code == 0 and not execution_error else "failed",
        "error_type": child_report.get("error_type") if child_report else None,
        "events": events,
        "summary": (
            child_report.get("summary", {}) if child_report
            else {
                "event_count": len(events),
                "dropped_events": 0,
                "max_events": max_events,
                "max_seconds": max_seconds,
            }
        ),
        "process": {
            "pid": process_id,
            "timed_out": timed_out,
            "exit_code": exit_code,
            "command_arguments_captured": False,
            "shell_used": False,
        },
        "execution": {
            "explicitly_opted_in": True,
            "sandboxed": False,
            "code_execution": True,
            "network_access_restricted": False,
            "environment_filtered": True,
            "sensitive_environment_variables_removed": (
                removed_sensitive_environment_variables
            ),
            "arguments_captured": False,
            "environment_captured": False,
            "stdout_stderr_captured": False,
        },
    }

    root_cause = analyze_root_cause(runtime_report, report.nodes, report.edges)
    runtime_report["root_cause"] = root_cause
    runtime_report["timeline"] = rebuild_timeline(events)
    _attach_runtime_graph(report, events)
    report.analyses["runtime"] = runtime_report
    if root_cause.get("status") == "correlated":
        component = root_cause.get("root_component") or {}
        report.findings.append(Finding(
            "runtime_unhandled_exception",
            "high",
            "An unhandled exception was observed during the opted-in Python runtime session.",
            Evidence(
                str(component.get("path", runtime_report["script"])),
                component.get("line"),
                f"{root_cause.get('exception_type', 'Exception')}; "
                f"root-cause confidence={root_cause.get('confidence', 0.0):.2f}",
            ),
        ))
    if database is not None:
        database.save_runtime_session(runtime_report)
    write_report(report, destination)
    return runtime_report
