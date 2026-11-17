from pathlib import Path

import pytest

from xray.core.models import Node
from xray.plugins import AnalysisContext, AnalysisResult, PluginRegistry


class ToyAnalyzer:
    name = "toy-analyzer"
    extensions = (".toy",)

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        node = Node(
            f"toy:{context.relative_path}",
            "toy-component",
            "sample",
            context.relative_path,
            1,
        )
        return AnalysisResult(nodes=[node])


def test_registry_dispatches_plugin_by_extension() -> None:
    registry = PluginRegistry.with_builtins()
    registry.register(ToyAnalyzer())
    plugin = registry.analyzers_for(".TOY")
    assert len(plugin) == 1
    assert plugin[0].name == "toy-analyzer"


def test_registry_rejects_duplicate_plugin_names() -> None:
    registry = PluginRegistry()
    registry.register(ToyAnalyzer())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(ToyAnalyzer())


def test_registry_rejects_invalid_plugin_contract() -> None:
    registry = PluginRegistry()
    with pytest.raises(TypeError):
        registry.register(object())  # type: ignore[arg-type]
