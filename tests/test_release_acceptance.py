from __future__ import annotations

import json
from pathlib import Path

from xray.scanner import scan_project


def test_release_scan_surfaces_core_analysis_and_redacts_secrets(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "release-fixture"\ndependencies = ["requests>=2.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
        encoding="utf-8",
    )
    secret = "synthetic_release_api_token_123456789"
    (tmp_path / "main.py").write_text(
        f'API_TOKEN = "{secret}"\n'
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

    report = scan_project(tmp_path)
    payload = json.dumps(report.to_dict(), ensure_ascii=False)
    function_nodes = [
        node for node in report.nodes
        if node.kind == "function" and node.path == "main.py"
    ]

    assert any(node.name == "endpoint" for node in function_nodes)
    assert any(node.kind == "file" and node.path == "main.py" for node in report.nodes)
    assert any(edge.relation == "contains" for edge in report.edges)
    assert report.analyses["dependencies"]["summary"]["dependency_count"] >= 1
    assert report.analyses["permissions"]["summary"]["items_found"] >= 1
    assert report.analyses["data_flows"]["summary"]["flow_count"] >= 1
    assert any(
        finding.rule_id == "sensitive_assignment"
        for finding in report.findings
    )
    assert secret not in payload
    assert report.coverage["graph_integrity_errors"] == []
    assert report.coverage["code_execution"] is False
    assert report.coverage["network_access"] is False


def test_release_dashboard_exposes_interactive_accessible_analysis_views() -> None:
    web_root = Path(__file__).resolve().parents[1] / "src" / "xray" / "web"
    html = (web_root / "index.html").read_text(encoding="utf-8")
    javascript = (web_root / "app.js").read_text(encoding="utf-8")

    assert '<html lang="ar" dir="rtl">' in html
    for section_id in (
        'id="files"',
        'id="graph"',
        'id="flows"',
        'id="errors"',
        'id="deps"',
        'id="security"',
        'id="changes"',
        'id="runtime"',
    ):
        assert section_id in html

    assert 'related.filter(function(node){return node.kind==="function";})' in javascript
    assert "الدوال الموجودة في الملف" in javascript
    assert 'group.setAttribute("role","button")' in javascript
    assert 'group.setAttribute("aria-label"' in javascript
    assert 'group.addEventListener("keydown"' in javascript
    assert "function openSource(path)" in javascript
    assert "openSource(e.path)" in javascript
    assert "innerHTML" not in javascript
    assert "eval(" not in javascript
