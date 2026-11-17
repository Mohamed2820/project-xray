from pathlib import Path

from xray.scanner import scan_project


def test_phase_three_analyses_are_connected_to_the_scan_report(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "sample"\ndependencies = ["requests>=2.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "def endpoint(request, cursor):\n"
        "    query = request.args.get('q')\n"
        "    cursor.execute(query)\n",
        encoding="utf-8",
    )
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        "</manifest>",
        encoding="utf-8",
    )
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: ci\non: push\npermissions:\n  contents: read\n"
        "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    decision = tmp_path / "docs" / "decisions" / "ADR-0001.md"
    decision.parent.mkdir(parents=True)
    decision.write_text(
        "# ADR-0001: Data store\n\nStatus: Accepted\n\n"
        "## Context\nNeed history.\n\n"
        "## Decision\nUse SQLite.\n\n"
        "## Consequences\nHistory is local.\n",
        encoding="utf-8",
    )

    report = scan_project(tmp_path)

    assert report.schema_version == "1.2"
    assert report.analyses["dependencies"]["summary"]["dependency_count"] == 1
    assert report.analyses["permissions"]["summary"]["items_found"] >= 1
    assert report.analyses["data_flows"]["summary"]["flow_count"] == 1
    assert report.analyses["engineering_decisions"]["summary"]["complete_records"] == 1
    assert report.coverage["graph_integrity_errors"] == []
    assert report.coverage["code_execution"] is False
    assert report.coverage["network_access"] is False
    assert all(item.get("sha256") for item in report.files)
