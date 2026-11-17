"""Explicit, extensible analyzer plugin registry.

Built-in plugins are registered by default. Third-party entry points are only
loaded when the caller explicitly requests discovery; loading trusted installed
plugins imports their code into the X-Ray process.
"""
from __future__ import annotations

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
        nodes, edges = analyze_python(context.path, context.relative_path)
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
        name = plugin.name.strip()
        if not name:
            raise ValueError("Plugin name must not be empty.")
        if name in self._plugins:
            raise ValueError(f"Plugin already registered: {name}")
        extensions = tuple(
            sorted({extension.lower() for extension in plugin.extensions})
        )
        if not extensions or any(
            not extension.startswith(".") or extension == "." for extension in extensions
        ):
            raise ValueError("Plugins must declare one or more dotted file extensions.")
        self._plugins[name] = plugin
        for extension in extensions:
            self._by_extension.setdefault(extension, []).append(plugin)

    def analyzers_for(self, extension: str) -> tuple[AnalyzerPlugin, ...]:
        return tuple(self._by_extension.get(extension.lower(), ()))

    def load_entry_points(self) -> tuple[str, ...]:
        """Load installed plugin entry points; this imports trusted plugin code."""
        loaded_names: list[str] = []
        discovered = entry_points()
        selected = (
            discovered.select(group=self.entry_point_group)
            if hasattr(discovered, "select")
            else discovered.get(self.entry_point_group, ())
        )
        for entry_point in sorted(selected, key=lambda item: item.name):
            candidate = entry_point.load()
            plugin = candidate() if isinstance(candidate, type) else candidate
            self.register(plugin)
            loaded_names.append(plugin.name)
        return tuple(loaded_names)
