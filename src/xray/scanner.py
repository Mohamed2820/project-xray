"""Plugin-driven, bounded project indexing and static analysis."""
from __future__ import annotations

from pathlib import Path

from xray.analyzers.secrets import scan_secrets
from xray.connectors import LocalFilesystemConnector, ProjectConnector
from xray.core.models import Node, ScanReport
from xray.graph import ProjectGraph
from xray.plugins import AnalysisContext, PluginRegistry

MAX_FILE_BYTES = 1_000_000
LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rs": "rust", ".c": "c", ".h": "c-header",
    ".cpp": "cpp", ".cs": "csharp", ".php": "php", ".rb": "ruby",
}


class ProjectScanner:
    """Orchestrates connector traversal, analyzer plugins, and security checks."""

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        max_file_bytes: int = MAX_FILE_BYTES,
    ) -> None:
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        self.registry = registry or PluginRegistry.with_builtins()
        self.max_file_bytes = max_file_bytes

    def scan(self, connector: ProjectConnector) -> ScanReport:
        report = ScanReport(root=str(connector.root))
        for entry in connector.iter_files():
            language = LANGUAGE_BY_SUFFIX.get(entry.path.suffix.lower(), "unknown")
            record = {
                "path": entry.relative_path,
                "size_bytes": entry.size_bytes,
                "language": language,
                "status": "inventoried",
                "analyzers": [],
            }
            report.files.append(record)
            file_node_id = f"file:{entry.relative_path}"
            report.nodes.append(
                Node(file_node_id, "file", entry.relative_path, entry.relative_path)
            )
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
                )
                try:
                    result = plugin.analyze(context)
                except Exception as error:  # Plugin boundary; do not leak source data.
                    errors.append(
                        {"plugin": plugin.name, "error": type(error).__name__}
                    )
                    continue
                report.nodes.extend(result.nodes)
                report.edges.extend(result.edges)
                record["analyzers"].append(plugin.name)

            report.findings.extend(scan_secrets(entry.path, entry.relative_path))
            if errors:
                record["status"] = "analysis_error"
                record["analysis_errors"] = errors
            elif analyzers and record["analyzers"]:
                record["status"] = "analyzed"
            elif not analyzers:
                record["status"] = "inventory_only"

        report.nodes = list({node.id: node for node in report.nodes}.values())
        graph = ProjectGraph(report.nodes, report.edges)
        report.coverage = {
            "filesystem_inventory": "complete_with_exclusions",
            "registered_analyzers": [plugin.name for plugin in self.registry.plugins],
            "analyzed_files": sum(
                item["status"] == "analyzed" for item in report.files
            ),
            "inventory_only_files": sum(
                item["status"] == "inventory_only" for item in report.files
            ),
            "python_ast": (
                "supported"
                if self.registry.analyzers_for(".py")
                else "not_registered"
            ),
            "other_language_semantics": "plugin_dependent",
            "runtime": "not_collected",
            "code_execution": False,
            "network_access": False,
            "max_file_bytes": self.max_file_bytes,
            "graph_integrity_errors": graph.validate(),
            "connector_errors": getattr(connector, "errors", []),
        }
        return report


def scan_project(root: Path, max_file_bytes: int = MAX_FILE_BYTES) -> ScanReport:
    """Backward-compatible convenience API for a local project directory."""
    connector = LocalFilesystemConnector(root)
    return ProjectScanner(max_file_bytes=max_file_bytes).scan(connector)
