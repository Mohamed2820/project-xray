from pathlib import Path

from xray.analyzers.python import analyze_python


def test_analyzer_tracks_classes_methods_async_functions_and_calls(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sample.py"
    source.write_text(
        "class Worker:\n"
        "    def run(self):\n"
        "        execute()\n"
        "    async def wait(self):\n"
        "        await_ready()\n",
        encoding="utf-8",
    )

    nodes, edges = analyze_python(source, "sample.py")
    names = {(node.kind, node.name) for node in nodes}
    assert ("class", "Worker") in names
    assert ("function", "Worker.run") in names
    assert ("function", "Worker.wait") in names
    assert ("call", "execute") in names
    assert ("call", "await_ready") in names
    assert any(edge.relation == "contains" for edge in edges)
    assert any(edge.relation == "calls" for edge in edges)


def test_analyzer_records_imports_with_evidence(tmp_path: Path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("import json\nfrom pathlib import Path\n", encoding="utf-8")

    nodes, edges = analyze_python(source, "sample.py")
    imports = [node for node in nodes if node.kind == "import"]
    assert {node.name for node in imports} == {"json", "pathlib"}
    assert all(edge.evidence.line in {1, 2} for edge in edges)
