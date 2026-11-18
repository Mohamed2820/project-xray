from pathlib import Path

import pytest

from xray.connectors.base import FileEntry
from xray.connectors.filesystem import LocalFilesystemConnector
from xray.core.engine import XRayEngine
from xray.core.models import Node
from xray.plugins import AnalysisContext, AnalysisResult, PluginRegistry
from xray.scanner import ProjectScanner


class TinyAnalyzer:
    name = "tiny-analyzer"
    extensions = (".tiny",)

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        return AnalysisResult(
            nodes=[
                Node(
                    f"tiny:{context.relative_path}",
                    "component",
                    context.path.stem,
                    context.relative_path,
                )
            ]
        )


def test_engine_uses_custom_connector_and_plugin(tmp_path: Path) -> None:
    (tmp_path / "unit.tiny").write_text("data", encoding="utf-8")
    registry = PluginRegistry.with_builtins()
    registry.register(TinyAnalyzer())
    engine = XRayEngine(scanner=ProjectScanner(registry=registry))
    report = engine.scan(LocalFilesystemConnector(tmp_path))
    assert report.files[0]["status"] == "analyzed"
    assert any(node.id == "tiny:unit.tiny" for node in report.nodes)
    assert report.coverage["code_execution"] is False


def test_connector_rejects_symlink_root(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        LocalFilesystemConnector(alias)


def test_scanner_enforces_file_size_limit(tmp_path: Path) -> None:
    (tmp_path / "large.py").write_text("x" * 100, encoding="utf-8")
    report = ProjectScanner(max_file_bytes=10).scan(LocalFilesystemConnector(tmp_path))
    assert report.files[0]["status"] == "skipped_size_limit"


def test_connector_enforces_depth_limit(tmp_path: Path) -> None:
    deep = tmp_path / "one" / "two"
    deep.mkdir(parents=True)
    (deep / "file.txt").write_text("x", encoding="utf-8")
    connector = LocalFilesystemConnector(tmp_path, max_depth=0)
    list(connector.iter_files())
    assert connector.limit_reached == "max_depth"


def test_connector_enforces_entry_limit(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"{index}.txt").write_text("x", encoding="utf-8")
    connector = LocalFilesystemConnector(tmp_path, max_entries=2)
    list(connector.iter_files())
    assert connector.limit_reached == "max_entries"


def test_scanner_does_not_disclose_paths_from_untrusted_connector_entries(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside-secret-name.py"
    outside.write_text("print('not scanned')\n", encoding="utf-8")

    class UntrustedConnector:
        @property
        def root(self) -> Path:
            return root

        def iter_files(self):
            yield FileEntry(outside, "../outside-secret-name.py", outside.stat().st_size)

    report = ProjectScanner().scan(UntrustedConnector())

    assert report.files == []
    assert all(node.path != "../outside-secret-name.py" for node in report.nodes)
    assert report.coverage["unsafe_connector_entries"] == 1
    assert report.coverage["scan_complete"] is False
    assert report.coverage["scan_limit_reached"] == "unsafe_or_changed_connector_entry"
