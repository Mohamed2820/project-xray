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


def test_entry_point_loading_requires_explicit_allowlist() -> None:
    registry = PluginRegistry()
    with pytest.raises(ValueError, match="allowlist"):
        registry.load_entry_points([])


def test_entry_point_loading_uses_only_approved_names(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeEntryPoint:
        def __init__(self, name: str) -> None:
            self.name = name

        def load(self):
            return ToyAnalyzer

    class FakeEntryPoints(list):
        def select(self, *, group: str):
            assert group == "xray.analyzers"
            return self

    monkeypatch.setattr(
        "xray.plugins.entry_points",
        lambda: FakeEntryPoints([FakeEntryPoint("approved"), FakeEntryPoint("unapproved")]),
    )
    registry = PluginRegistry()
    assert registry.load_entry_points(["approved"]) == ("toy-analyzer",)
