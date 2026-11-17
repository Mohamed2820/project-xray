from pathlib import Path

from xray.analyzers.dataflow import analyze_data_flows


def test_intra_function_taint_flow_to_sql_and_command_sinks(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def endpoint(request):\n"
        "    query = request.args.get('q')\n"
        "    cursor.execute(query)\n"
        "    subprocess.run(query, shell=True)\n",
        encoding="utf-8",
    )
    records = [{"path": "app.py", "status": "analyzed"}]

    flows, nodes, edges, findings, summary = analyze_data_flows(
        tmp_path, records
    )

    assert {flow["sink_type"] for flow in flows} == {
        "sql_query", "command_execution"
    }
    assert all(flow["source_line"] == 2 for flow in flows)
    assert all(flow["sink_line"] in {3, 4} for flow in flows)
    assert len(edges) == 2
    assert any(item.kind == "data_source" for item in nodes)
    assert any(item.kind == "data_sink" for item in nodes)
    assert len(findings) == 2
    assert summary["model"] == "intra_function_ast_taint_heuristic"


def test_dataflow_does_not_scan_unanalyzed_or_non_python_files(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "def run(request):\n    eval(request.args.get('x'))\n",
        encoding="utf-8",
    )
    flows, nodes, edges, findings, summary = analyze_data_flows(
        tmp_path,
        [
            {"path": "main.py", "status": "inventory_only"},
            {"path": "app.js", "status": "analyzed"},
        ],
    )
    assert flows == []
    assert nodes == []
    assert edges == []
    assert findings == []
    assert summary["python_files_analyzed"] == 0



def test_extremely_deep_expression_is_skipped_without_crashing(tmp_path: Path) -> None:
    source = tmp_path / "deep.py"
    source.write_text("def run():\n    value = " + "(" * 1500 + "1" + ")" * 1500, encoding="utf-8")
    flows, nodes, edges, findings, summary = analyze_data_flows(
        tmp_path, [{"path": "deep.py", "status": "analyzed"}]
    )
    assert flows == []
    assert edges == []
    assert findings == []
    assert summary["python_files_skipped"] == 1
