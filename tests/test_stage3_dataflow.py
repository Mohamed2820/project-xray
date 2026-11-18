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


def test_taint_propagates_through_explicit_import_into_another_file(
    tmp_path: Path,
) -> None:
    from xray.scanner import scan_project

    project = tmp_path / "multi-module"
    (project / "api").mkdir(parents=True)
    (project / "api" / "__init__.py").write_text("", encoding="utf-8")
    (project / "api" / "handlers.py").write_text(
        "from api.database import write_user\\n"
        "def update(request, cursor):\\n"
        "    user_id = request.args.get('id')\\n"
        "    return write_user(cursor, user_id)\\n",
        encoding="utf-8",
    )
    (project / "api" / "database.py").write_text(
        "def write_user(cursor, user_id):\\n"
        "    query = 'UPDATE users SET id = ' + user_id\\n"
        "    return cursor.execute(query)\\n",
        encoding="utf-8",
    )

    report = scan_project(project)
    flows = report.analyses["data_flows"]["items"]

    cross_file = [
        flow for flow in flows
        if flow.get("source_path") == "api/handlers.py"
        and flow.get("sink_path") == "api/database.py"
    ]
    assert cross_file
    assert all(flow["cross_file"] is True for flow in cross_file)
    assert all(flow["confidence"] == "heuristic_interprocedural" for flow in cross_file)
    assert any(
        item.rule_id == "possible_tainted_data_to_sql_query"
        and item.evidence.path == "api/database.py"
        for item in report.findings
    )


def test_interprocedural_analysis_is_bounded_for_recursive_calls(tmp_path: Path) -> None:
    from xray.scanner import scan_project

    project = tmp_path / "recursive"
    project.mkdir()
    (project / "main.py").write_text(
        "def recurse(value):\\n"
        "    return recurse(value)\\n"
        "def entry(request):\\n"
        "    return recurse(request.args.get('x'))\\n",
        encoding="utf-8",
    )
    report = scan_project(project)
    assert report.analyses["data_flows"]["summary"]["max_interprocedural_depth"] == 8
