"""Bounded filesystem inventory; never follows symlinks or executes project code."""
from __future__ import annotations

from pathlib import Path

from xray.analyzers.python import analyze_python
from xray.analyzers.secrets import scan_secrets
from xray.core.models import ScanReport

EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "build", "dist", "coverage",
}
MAX_FILE_BYTES = 1_000_000
LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rs": "rust", ".c": "c", ".h": "c-header",
    ".cpp": "cpp", ".cs": "csharp", ".php": "php", ".rb": "ruby",
}


def scan_project(root: Path, max_file_bytes: int = MAX_FILE_BYTES) -> ScanReport:
    root = root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    report = ScanReport(root=str(root))
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        item = {"path": relative.as_posix(), "size_bytes": size,
                "language": LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown")}
        if size > max_file_bytes:
            item["status"] = "skipped_size_limit"
            report.files.append(item)
            continue
        item["status"] = "inventoried"
        report.files.append(item)
        if path.suffix.lower() == ".py":
            try:
                nodes, edges = analyze_python(path, relative.as_posix())
                report.nodes.extend(nodes)
                report.edges.extend(edges)
            except (SyntaxError, UnicodeDecodeError, OSError) as exc:
                item["status"] = "analysis_error"
                item["analysis_error"] = type(exc).__name__
        report.findings.extend(scan_secrets(path, relative.as_posix()))
    report.coverage = {
        "filesystem_inventory": "complete_with_exclusions",
        "python_ast": "supported",
        "other_language_semantics": "not_implemented",
        "runtime": "not_collected",
        "code_execution": False,
        "network_access": False,
        "max_file_bytes": max_file_bytes,
    }
    return report
