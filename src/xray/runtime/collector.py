"""Bounded Python runtime event collection without argument or local-value capture."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, Callable

RUNTIME_AUDIT_EVENTS = {
    "subprocess.Popen": "process",
    "os.system": "process",
    "os.exec": "process",
    "os.spawn": "process",
    "socket.connect": "network",
    "socket.bind": "network",
    "socket.getaddrinfo": "network",
    "os.remove": "filesystem",
    "os.rename": "filesystem",
    "os.mkdir": "filesystem",
    "os.rmdir": "filesystem",
    "os.chdir": "filesystem",
    "os.chmod": "filesystem",
    "threading.Thread.start": "thread",
}

EventSink = Callable[[dict[str, Any]], None]


class RuntimeCollector:
    """Collect in-project Python calls and selected audit events under hard limits.

    Function arguments, local variables, return values, environment variables,
    file contents, command arguments, and network payloads are never recorded.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_events: int = 10_000,
        max_seconds: float = 120.0,
        sink: EventSink | None = None,
        origin_ns: int | None = None,
    ) -> None:
        if max_events < 1 or max_events > 100_000:
            raise ValueError("max_events must be between 1 and 100000")
        if not 0 < max_seconds <= 600:
            raise ValueError("max_seconds must be greater than 0 and at most 600")
        requested_root = Path(root).expanduser()
        if requested_root.is_symlink():
            raise ValueError("Runtime project root must not be a symbolic link.")
        self.root = requested_root.resolve(strict=True)
        if not self.root.is_dir():
            raise NotADirectoryError(self.root)
        self.max_events = max_events
        self.max_seconds = max_seconds
        self.sink = sink
        self.origin_ns = origin_ns
        self.events: list[dict[str, Any]] = []
        self.dropped_events = 0
        self.time_limit_reached = False
        self.event_limit_reached = False
        self.started_ns = 0
        self._lock = threading.RLock()
        self._active = False
        self._sequence = 0
        self._frame_starts: dict[int, int] = {}
        self._previous_profile: Any = None
        self._previous_thread_profile: Any = None
        self._audit_installed = False
        self._internal_package = Path(__file__).resolve().parent.parent

    def _project_path(self, filename: str) -> str | None:
        if not filename or filename.startswith("<"):
            return None
        try:
            path = Path(filename).resolve(strict=False)
            relative = path.relative_to(self.root)
            if path.is_relative_to(self._internal_package):
                return None
            excluded = {".venv", "venv", "site-packages", "__pycache__"}
            if any(part in excluded for part in relative.parts):
                return None
            return relative.as_posix()
        except (OSError, RuntimeError, ValueError):
            return None

    def _component(
        self, frame: FrameType
    ) -> tuple[str, str, int, str] | None:
        code = frame.f_code
        relative = self._project_path(code.co_filename)
        if relative is None:
            return None
        line = int(frame.f_lineno)
        function = str(getattr(code, "co_qualname", code.co_name))[:256]
        identifier = f"runtime-function:{relative}:{code.co_firstlineno}:{function}"
        return identifier, relative, line, function

    def record(
        self,
        event_type: str,
        *,
        component_id: str | None = None,
        path: str | None = None,
        line: int | None = None,
        function: str | None = None,
        caller_component_id: str | None = None,
        duration_ns: int | None = None,
        detail: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        now_ns = time.monotonic_ns()
        with self._lock:
            if not self._active:
                return None
            if now_ns - self.started_ns > int(self.max_seconds * 1_000_000_000):
                self.time_limit_reached = True
                self.dropped_events += 1
                return None
            if len(self.events) >= self.max_events:
                self.event_limit_reached = True
                self.dropped_events += 1
                return None
            self._sequence += 1
            event: dict[str, Any] = {
                "sequence": self._sequence,
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "elapsed_ns": now_ns - self.started_ns,
                "process_id": os.getpid(),
                "thread_id": threading.get_ident(),
                "event_type": event_type,
                "component_id": component_id,
                "path": path,
                "line": line,
                "function": function,
                "caller_component_id": caller_component_id,
                "duration_ns": duration_ns,
                "detail": detail,
            }
            if extra:
                event.update(extra)
            self.events.append(event)
            if self.sink is not None:
                try:
                    self.sink(event)
                except Exception:
                    self.dropped_events += 1
            return event

    def _profile(self, frame: FrameType, event: str, arg: Any) -> None:
        if not self._active or event not in {"call", "return"}:
            return
        component = self._component(frame)
        if component is None:
            return
        identifier, path, line, function = component
        frame_key = id(frame)
        if event == "call":
            self._frame_starts[frame_key] = time.monotonic_ns()
            caller = self._component(frame.f_back) if frame.f_back is not None else None
            self.record(
                "function_call",
                component_id=identifier,
                path=path,
                line=line,
                function=function,
                caller_component_id=caller[0] if caller else None,
            )
            return
        started = self._frame_starts.pop(frame_key, None)
        self.record(
            "function_return",
            component_id=identifier,
            path=path,
            line=line,
            function=function,
            duration_ns=max(0, time.monotonic_ns() - started) if started else None,
        )

    def _audit(self, event: str, args: tuple[Any, ...]) -> None:
        event_category = RUNTIME_AUDIT_EVENTS.get(event)
        if event_category is None or not self._active:
            return
        # Deliberately discard audit arguments: they can contain secrets, paths,
        # command strings, credentials, or sensitive user data.
        self.record(
            f"{event_category}_event",
            detail=f"python_audit:{event}",
        )

    def record_exception(self, error: BaseException) -> dict[str, Any] | None:
        import traceback

        stack: list[dict[str, Any]] = []
        extracted = traceback.extract_tb(error.__traceback__)
        for frame in extracted[-100:]:
            relative = self._project_path(frame.filename)
            if relative is None:
                continue
            stack.append({
                "path": relative,
                "line": int(frame.lineno),
                "function": str(frame.name)[:256],
            })
        deepest = stack[-1] if stack else {}
        message = f"{type(error).__name__}: {error}"
        try:
            from xray.analyzers.secrets import redact_sensitive_text

            message = redact_sensitive_text(message)
        except Exception:
            message = f"{type(error).__name__}: [message omitted]"
        message = message[:500]
        return self.record(
            "exception",
            path=deepest.get("path"),
            line=deepest.get("line"),
            function=deepest.get("function"),
            detail=message,
            extra={
                "exception_type": type(error).__name__[:128],
                "stack_trace": stack,
            },
        )

    def start(self) -> RuntimeCollector:
        if self._active:
            raise RuntimeError("Runtime collector is already active.")
        self.started_ns = self.origin_ns or time.monotonic_ns()
        self._active = True
        self._previous_profile = sys.getprofile()
        self._previous_thread_profile = threading.getprofile()
        sys.setprofile(self._profile)
        threading.setprofile(self._profile)
        if not self._audit_installed:
            sys.addaudithook(self._audit)
            self._audit_installed = True
        self.record("runtime_started", detail="Python runtime collection enabled.")
        return self

    def stop(self) -> None:
        if not self._active:
            return
        self.record("runtime_stopped", detail="Python runtime collection disabled.")
        self._active = False
        sys.setprofile(self._previous_profile)
        threading.setprofile(self._previous_thread_profile)
        self._frame_starts.clear()

    def summary(self) -> dict[str, Any]:
        duration = max(0, time.monotonic_ns() - self.started_ns) if self.started_ns else 0
        return {
            "event_count": len(self.events),
            "dropped_events": self.dropped_events,
            "time_limit_reached": self.time_limit_reached,
            "event_limit_reached": self.event_limit_reached,
            "telemetry_complete": (
                self.dropped_events == 0
                and not self.time_limit_reached
                and not self.event_limit_reached
            ),
            "duration_ns": duration,
            "max_events": self.max_events,
            "max_seconds": self.max_seconds,
            "arguments_captured": False,
            "local_variables_captured": False,
            "return_values_captured": False,
            "audit_arguments_captured": False,
        }

    def __enter__(self) -> RuntimeCollector:
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc is not None and not (
            isinstance(exc, SystemExit) and exc.code in {None, 0}
        ):
            self.record_exception(exc)
        self.stop()
