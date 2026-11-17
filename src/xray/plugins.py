"""Explicit plugin registry; third-party plugins are trusted in-process code."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Protocol, runtime_checkable

from xray.analyzers.python import analyze_python
from xray.core.models import Edge, Node

ENTRY_POINT_GROUP = "xray.analyzers"


@dataclass(frozen=True)
class AnalysisContext:
    root: Path
    path: Path
    relative_path: str
    size_bytes: int
    max_file_bytes: int = 1_000_000


@dataclass
class AnalysisResult:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)


@runtime_checkable
class AnalyzerPlugin(Protocol):
    name: str
    extensions: tuple[str, ...]

    def analyze(self, context: AnalysisContext) -> AnalysisResult: ...


class PythonAnalyzerPlugin:
    """Python AST analyzer bundled with X-Ray."""

    name = "python-ast"
    extensions = (".py",)

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        nodes, edges = analyze_python(
            context.path, context.relative_path, max_bytes=context.max_file_bytes
        )
        return AnalysisResult(nodes=nodes, edges=edges)


class PluginRegistry:
    """Maps file extensions to explicitly registered analyzer plugins."""

    def __init__(self, entry_point_group: str = ENTRY_POINT_GROUP) -> None:
        self.entry_point_group = entry_point_group
        self._plugins: dict[str, AnalyzerPlugin] = {}
        self._by_extension: dict[str, list[AnalyzerPlugin]] = {}

    @classmethod
    def with_builtins(cls) -> PluginRegistry:
        registry = cls()
        registry.register(PythonAnalyzerPlugin())
        return registry

    @property
    def plugins(self) -> tuple[AnalyzerPlugin, ...]:
        return tuple(self._plugins.values())

    def register(self, plugin: AnalyzerPlugin) -> None:
        if not isinstance(plugin, AnalyzerPlugin):
            raise TypeError("Plugin must provide name, extensions, and analyze(context).")
        if not isinstance(plugin.name, str) or not plugin.name.strip():
            raise ValueError("Plugin name must be a non-empty string.")
        name = plugin.name.strip()
        if name in self._plugins:
            raise ValueError(f"Plugin already registered: {name}")
        declared = tuple(plugin.extensions)
        extensions = tuple(sorted({
            extension.lower() for extension in declared if isinstance(extension, str)
        }))
        if not extensions or len(extensions) != len(declared) or any(
            not extension.startswith(".") or extension == "." for extension in extensions
        ):
            raise ValueError("Plugins must declare one or more dotted file extensions.")
        self._plugins[name] = plugin
        for extension in extensions:
            self._by_extension.setdefault(extension, []).append(plugin)

    def analyzers_for(self, extension: str) -> tuple[AnalyzerPlugin, ...]:
        return tuple(self._by_extension.get(extension.lower(), ()))

    def load_entry_points(self, allowlist: Iterable[str]) -> tuple[str, ...]:
        """Load only explicitly named trusted entry points into this process.

        This is not a sandbox. A selected plugin executes with X-Ray's process
        permissions and must be independently reviewed before it is trusted.
        """
        approved = {
            name.strip() for name in allowlist
            if isinstance(name, str) and name.strip()
        }
        if not approved:
            raise ValueError("An explicit non-empty trusted plugin allowlist is required.")
        discovered = entry_points()
        selected = (
            discovered.select(group=self.entry_point_group)
            if hasattr(discovered, "select")
            else discovered.get(self.entry_point_group, ())
        )
        available = {item.name: item for item in selected}
        missing = sorted(approved - available.keys())
        if missing:
            raise ValueError(f"Trusted plugin entry point(s) not found: {', '.join(missing)}")
        loaded_names: list[str] = []
        for name in sorted(approved):
            candidate = available[name].load()
            plugin = candidate() if isinstance(candidate, type) else candidate
            self.register(plugin)
            loaded_names.append(plugin.name)
        return tuple(loaded_names)
