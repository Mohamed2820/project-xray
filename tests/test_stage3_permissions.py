from pathlib import Path

from xray.analyzers.permissions import analyze_permissions


def test_android_ci_and_container_permissions_are_reported(tmp_path: Path) -> None:
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        '<uses-permission android:name="android.permission.READ_SMS"/>'
        '</manifest>',
        encoding="utf-8",
    )
    workflow = tmp_path / ".github" / "workflows" / "deploy.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: deploy\non: push\npermissions:\n"
        "  contents: write\n"
        "jobs:\n  deploy:\n    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.13\nUSER root\n", encoding="utf-8")

    records = [
        {"path": "AndroidManifest.xml"},
        {"path": ".github/workflows/deploy.yml"},
        {"path": "Dockerfile"},
    ]
    permissions, nodes, findings, summary = analyze_permissions(tmp_path, records)
    rules = {item.rule_id for item in findings}

    assert any(item["name"] == "android.permission.CAMERA" for item in permissions)
    assert any(item["name"] == "android.permission.READ_SMS" for item in permissions)
    assert "ci_write_permission" in rules
    assert "ci_action_not_sha_pinned" in rules
    assert "container_runs_as_root" in rules
    assert len(nodes) == len(permissions)
    assert summary["items_found"] == len(permissions)


def test_malformed_android_manifest_is_reported_as_incomplete(tmp_path: Path) -> None:
    (tmp_path / "AndroidManifest.xml").write_text("<manifest>", encoding="utf-8")
    _, _, findings, _ = analyze_permissions(
        tmp_path, [{"path": "AndroidManifest.xml"}]
    )
    assert findings[0].rule_id == "permission_android_manifest_parse_error"
