"""Plugin-driven static analysis with bounded reads and evidence-backed reports."""
from __future__ import annotations

import hashlib
import math
import os
import stat
import time
from pathlib import Path, PurePosixPath

from xray.analyzers.dataflow import analyze_data_flows
from xray.analyzers.decisions import analyze_decisions
from xray.analyzers.dependencies import analyze_dependencies
from xray.analyzers.permissions import analyze_permissions
from xray.analyzers.safe_io import open_project_file
from xray.analyzers.secrets import scan_secrets
from xray.connectors import LocalFilesystemConnector, ProjectConnector
from xray.core.models import Node, ScanReport
from xray.graph import ProjectGraph
from xray.plugins import AnalysisContext, PluginRegistry

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SCAN_SECONDS = 120.0

LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rs": "rust", ".c": "c", ".h": "c-header",
    ".cpp": "cpp", ".cs": "csharp", ".php": "php", ".rb": "ruby",
}


def _sha256_file(
    root: Path,
    relative_path: str,
    max_bytes: int,
    deadline: float,
) -> str | None:
    """Hash an in-root regular file using no-follow directory descriptors."""
    handle = open_project_file(root, relative_path)
    if handle is None:
        return None
    try:
        digest = hashlib.sha256()
        with handle:
            metadata = os.fstat(handle.fileno())
            if metadata.st_size > max_bytes:
                return None
            total = 0
            while True:
                if time.monotonic() >= deadline:
                    return None
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return None
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None

class ProjectScanner:
    """Orchestrates source inventory, language plugins, and security intelligence."""

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        max_file_bytes: int = MAX_FILE_BYTES,
        *,
        max_files: int = MAX_FILES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
        max_scan_seconds: float = MAX_SCAN_SECONDS,
        osv_database: Path | None = None,
    ) -> None:
        if max_file_bytes < 1 or max_files < 1 or max_total_bytes < 1:
            raise ValueError("File, file-count, and total-byte limits must be positive")
        if not math.isfinite(max_scan_seconds) or max_scan_seconds <= 0:
            raise ValueError("max_scan_seconds must be a finite positive number")
        self.registry = registry or PluginRegistry.with_builtins()
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_scan_seconds = max_scan_seconds
        self.osv_database = osv_database

    @staticmethod
    def _entry_is_safe(connector: ProjectConnector, entry: object) -> bool:
        try:
            relative = PurePosixPath(entry.relative_path)  # type: ignore[attr-defined]
            if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                return False
            path = entry.path  # type: ignore[attr-defined]
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                return False
            resolved = path.resolve(strict=True)
            resolved.relative_to(connector.root.resolve(strict=True))
            return metadata.st_size == entry.size_bytes  # type: ignore[attr-defined]
        except (AttributeError, OSError, ValueError):
            return False

    def scan(self, connector: ProjectConnector) -> ScanReport:
        started = time.monotonic()
        deadline = started + self.max_scan_seconds
        report = ScanReport(root=str(connector.root))
        file_count = 0
        total_bytes = 0
        hash_failures = 0
        limit_reason: str | None = None

        for entry in connector.iter_files():
            if time.monotonic() >= deadline:
                limit_reason = "max_scan_seconds"
                break
            if file_count >= self.max_files:
                limit_reason = "max_files"
                break
            file_count += 1
            record = {
                "path": entry.relative_path,
                "size_bytes": entry.size_bytes,
                "sha256": None,
                "language": LANGUAGE_BY_SUFFIX.get(entry.path.suffix.lower(), "unknown"),
                "status": "inventoried",
                "analyzers": [],
            }
            report.files.append(record)
            report.nodes.append(Node(
                f"file:{entry.relative_path}", "file",
                entry.relative_path, entry.relative_path,
            ))
            if entry.size_bytes < 0:
                record["status"] = "invalid_file_metadata"
                continue
            if total_bytes + entry.size_bytes > self.max_total_bytes:
                record["status"] = "skipped_total_size_limit"
                limit_reason = "max_total_bytes"
                break
            total_bytes += entry.size_bytes
            if not self._entry_is_safe(connector, entry):
                record["status"] = "changed_or_unsafe_file"
                hash_failures += 1
                continue

            record["sha256"] = _sha256_file(
                connector.root, entry.relative_path,
                self.max_total_bytes, deadline,
            )
            if record["sha256"] is None:
                hash_failures += 1
                if time.monotonic() >= deadline:
                    record["status"] = "hash_interrupted_time_limit"
                    limit_reason = "max_scan_seconds"
                    break

            if entry.size_bytes > self.max_file_bytes:
                record["status"] = "skipped_size_limit"
                continue

            analyzers = self.registry.analyzers_for(entry.path.suffix)
            errors: list[dict[str, str]] = []
            for plugin in analyzers:
                context = AnalysisContext(
                    root=connector.root,
                    path=entry.path,
                    relative_path=entry.relative_path,
                    size_bytes=entry.size_bytes,
                    max_file_bytes=self.max_file_bytes,
                )
                try:
                    result = plugin.analyze(context)
                    report.nodes.extend(result.nodes)
                    report.edges.extend(result.edges)
                    record["analyzers"].append(plugin.name)
                except Exception as error:
                    errors.append({"plugin": plugin.name, "error": type(error).__name__})
                if time.monotonic() >= deadline:
                    limit_reason = "max_scan_seconds"
                    break

            report.findings.extend(
                scan_secrets(
                    entry.path, entry.relative_path,
                    max_bytes=self.max_file_bytes, root=connector.root,
                )
            )
            if errors:
                record["status"] = "analysis_error"
                record["analysis_errors"] = errors
            elif analyzers and record["analyzers"]:
                record["status"] = "analyzed"
            elif not analyzers:
                record["status"] = "inventory_only"
            if limit_reason:
                break

        # The fixed set of recognized metadata/config files is also bounded by
        # max_file_bytes. These analyzers only read data; they never install or run it.
        dependency_records, dependency_nodes, dependency_edges, dependency_findings, dep_summary = (
            analyze_dependencies(
                connector.root, self.max_file_bytes, self.osv_database
            )
        )
        known_file_ids = {
            node.id for node in report.nodes if node.kind == "file"
        }
        report.nodes.extend(dependency_nodes)
        report.edges.extend(
            edge for edge in dependency_edges if edge.source in known_file_ids
        )
        report.findings.extend(dependency_findings)

        permission_records, permission_nodes, permission_findings, permission_summary = (
            analyze_permissions(
                connector.root, report.files, self.max_file_bytes, deadline=deadline
            )
        )
        report.nodes.extend(permission_nodes)
        report.findings.extend(permission_findings)

        data_flows, flow_nodes, flow_edges, flow_findings, flow_summary = (
            analyze_data_flows(
                connector.root, report.files, self.max_file_bytes,
                deadline=deadline,
            )
        )
        report.nodes.extend(flow_nodes)
        report.edges.extend(flow_edges)
        report.findings.extend(flow_findings)

        decisions, decision_summary = analyze_decisions(
            connector.root, report.files, self.max_file_bytes, deadline=deadline
        )
        if flow_summary["status"] == "partial" and not limit_reason:
            limit_reason = "data_flow_analysis_budget"
        if decision_summary["status"] == "partial" and not limit_reason:
            limit_reason = "decision_analysis_budget"
        if permission_summary["status"] == "partial" and not limit_reason:
            limit_reason = "permission_analysis_budget"

        report.nodes = list({node.id: node for node in report.nodes}.values())
        graph = ProjectGraph(report.nodes, report.edges)
        connector_limit = getattr(connector, "limit_reached", None)
        connector_errors = getattr(connector, "errors", [])
        if connector_limit and not limit_reason:
            limit_reason = f"connector_{connector_limit}"

        report.analyses = {
            "dependencies": {
                "items": dependency_records,
                "summary": dep_summary,
            },
            "permissions": {
                "items": permission_records,
                "summary": permission_summary,
            },
            "data_flows": {
                "items": data_flows,
                "summary": flow_summary,
            },
            "engineering_decisions": {
                "items": decisions,
                "summary": decision_summary,
            },
            "changes": {
                "status": "awaiting_snapshot_comparison",
                "added": [], "modified": [], "deleted": [],
            },
        }
        report.coverage = {
            "filesystem_inventory": (
                "partial_due_to_limits" if limit_reason
                else "partial_due_to_connector_errors" if connector_errors
                else "complete_with_exclusions"
            ),
            "scan_complete": limit_reason is None and not connector_errors,
            "scan_limit_reached": limit_reason,
            "registered_analyzers": [plugin.name for plugin in self.registry.plugins],
            "analyzed_files": sum(item["status"] == "analyzed" for item in report.files),
            "inventory_only_files": sum(
                item["status"] == "inventory_only" for item in report.files
            ),
            "files_seen": file_count,
            "bytes_considered": total_bytes,
            "hash_failures": hash_failures,
            "change_hash_coverage": "partial" if hash_failures else "complete",
            "limits": {
                "max_file_bytes": self.max_file_bytes,
                "max_files": self.max_files,
                "max_total_bytes": self.max_total_bytes,
                "max_scan_seconds": self.max_scan_seconds,
                "connector_max_entries": getattr(connector, "max_entries", None),
                "connector_max_depth": getattr(connector, "max_depth", None),
            },
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "python_ast": (
                "supported" if self.registry.analyzers_for(".py") else "not_registered"
            ),
            "other_language_semantics": "plugin_dependent",
            "dependency_analysis": dep_summary["status"],
            "permission_analysis": permission_summary["status"],
            "data_flow_analysis": flow_summary["status"],
            "decision_analysis": decision_summary["status"],
            "runtime": "not_collected",
            "code_execution": False,
            "network_access": False,
            "graph_integrity_errors": graph.validate(),
            "connector_errors": connector_errors,
            "connector_limit_reached": connector_limit,
            "connector_entries_visited": getattr(connector, "visited_entries", None),
        }
        return report


def scan_project(
    root: Path,
    max_file_bytes: int = MAX_FILE_BYTES,
    *,
    max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_scan_seconds: float = MAX_SCAN_SECONDS,
    osv_database: Path | None = None,
) -> ScanReport:
    """Backward-compatible convenience API for a local project directory."""
    connector = LocalFilesystemConnector(root)
    scanner = ProjectScanner(
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        max_scan_seconds=max_scan_seconds,
        osv_database=osv_database,
    )
    return scanner.scan(connector)
