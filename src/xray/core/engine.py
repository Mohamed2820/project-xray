"""Central X-Ray orchestration engine."""
from __future__ import annotations

from pathlib import Path

from xray.connectors import LocalFilesystemConnector, ProjectConnector
from xray.core.models import ScanReport
from xray.graph import ProjectGraph
from xray.scanner import ProjectScanner
from xray.storage.sqlite import SQLiteDataEngine


class XRayEngine:
    """Coordinates connectors, scanning plugins, graph generation, and storage."""

    def __init__(
        self,
        scanner: ProjectScanner | None = None,
        data_engine: SQLiteDataEngine | None = None,
    ) -> None:
        self.scanner = scanner or ProjectScanner()
        self.data_engine = data_engine
        self.last_graph: ProjectGraph | None = None

    @staticmethod
    def build_graph(report: ScanReport) -> ProjectGraph:
        """Build an indexed graph from a report for neighborhood/impact queries."""
        return ProjectGraph(report.nodes, report.edges)

    def scan(
        self,
        source: str | Path | ProjectConnector,
        *,
        persist: bool = False,
    ) -> ScanReport:
        """Scan a project; persistence is opt-in and never writes into the source."""
        if isinstance(source, (str, Path)):
            connector: ProjectConnector = LocalFilesystemConnector(source)
        elif isinstance(source, ProjectConnector):
            connector = source
        else:
            raise TypeError("source must be a path or a ProjectConnector")

        if persist:
            if self.data_engine is None:
                raise ValueError("persist=True requires a configured data engine")
            database = self.data_engine.database_path.resolve()
            try:
                database.relative_to(connector.root)
            except ValueError:
                pass
            else:
                raise ValueError(
                    "The SQLite database must be stored outside the scanned project."
                )

        report = self.scanner.scan(connector)
        self.last_graph = self.build_graph(report)
        if persist:
            self.data_engine.save_report(report)
        return report
