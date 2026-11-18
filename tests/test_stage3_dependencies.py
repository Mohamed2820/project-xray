import json
from pathlib import Path

from xray.analyzers.dependencies import analyze_dependencies


def test_python_lockfile_resolves_direct_and_transitive_and_offline_advisory(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\ndependencies = ["requests>=2.0", "urllib3>=1.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        '\n[[package]]\nname = "urllib3"\nversion = "1.26.2"\n'
        '\n[[package]]\nname = "idna"\nversion = "3.4"\n',
        encoding="utf-8",
    )
    osv = tmp_path / "osv.json"
    osv.write_text(json.dumps({
        "vulns": [{
            "id": "GHSA-fixture",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "urllib3"},
                "versions": ["1.26.2"],
            }],
        }],
    }), encoding="utf-8")

    items, nodes, edges, findings, summary = analyze_dependencies(
        tmp_path, osv_database=osv
    )

    assert summary["dependency_count"] == 3
    assert summary["direct_count"] == 2
    assert summary["transitive_count"] == 1
    assert any(
        item["name"] == "urllib3"
        and item["version"] == "1.26.2"
        and item["direct"]
        and item["advisory_ids"] == ["GHSA-fixture"]
        for item in items
    )
    assert any(item["name"] == "idna" and not item["direct"] for item in items)
    assert any(finding.rule_id == "dependency_known_advisory_match" for finding in findings)
    assert len(nodes) == 3
    assert len(edges) == 3
    assert summary["network_access"] is False


def test_npm_manifest_and_lockfile_are_merged_and_urls_redacted(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"left-pad":"^1.3.0"}}', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture", "dependencies": {"left-pad": "^1.3.0"}},
            "node_modules/left-pad": {
                "name": "left-pad", "version": "1.3.0",
                "resolved": (
                    "https://user:topsecret@packages.example/left-pad.tgz"
                    "?token=secretvalue"
                ),
            },
            "node_modules/left-pad/node_modules/sub-dep": {
                "name": "sub-dep", "version": "2.0.0",
            },
        },
    }), encoding="utf-8")

    items, _, _, _, summary = analyze_dependencies(tmp_path)
    left_pad = [item for item in items if item["name"] == "left-pad"]
    assert len(left_pad) == 1
    assert left_pad[0]["direct"] is True
    assert left_pad[0]["version"] == "1.3.0"
    assert "topsecret" not in repr(items)
    assert "secretvalue" not in repr(items)
    assert any(item["name"] == "sub-dep" and not item["direct"] for item in items)
    assert summary["network_access"] is False


def test_osv_symlink_input_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = tmp_path / "osv.json"
    target.write_text('{"vulns":[]}', encoding="utf-8")
    link = tmp_path / "osv-link.json"
    link.symlink_to(target)
    (root / "pyproject.toml").write_text(
        '[project]\ndependencies = ["example-package==1.0"]\n',
        encoding="utf-8",
    )
    items, _, _, _, summary = analyze_dependencies(root, osv_database=link)
    assert items
    assert summary["advisory_matches"] == 0



def test_malformed_manifests_and_osv_shapes_do_not_crash(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = 42\n[tool.poetry]\ndependencies = false\n',
        encoding="utf-8",
    )
    osv = tmp_path / "osv-malformed.json"
    osv.write_text(json.dumps({
        "vulns": [
            {"id": "BAD-1", "affected": None},
            {"id": "BAD-2", "affected": [{"package": None, "versions": "not-a-list"}]},
            {"id": "OK-1", "affected": [{
                "package": {"ecosystem": "PyPI", "name": "sample"},
                "versions": ["1.0"],
            }]},
        ],
    }), encoding="utf-8")

    items, _, _, findings, summary = analyze_dependencies(
        tmp_path, osv_database=osv
    )
    assert isinstance(items, list)
    assert isinstance(findings, list)
    assert summary["network_access"] is False



def test_manifest_field_type_confusion_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = 7\n[tool.poetry]\ndependencies = false\n',
        encoding="utf-8",
    )
    items, nodes, edges, findings, summary = analyze_dependencies(tmp_path)
    assert items == []
    assert nodes == []
    assert edges == []
    assert findings == []
    assert summary["dependency_count"] == 0



def test_editable_vcs_requirement_is_identified_and_url_redacted(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "-e git+https://user:private-password@git.example/repo.git#egg=sample-lib\n",
        encoding="utf-8",
    )
    items, _, _, findings, _ = analyze_dependencies(tmp_path)
    assert len(items) == 1
    assert items[0]["name"] == "sample-lib"
    assert "external_or_git_source" in items[0]["risk_flags"]
    assert "private-password" not in repr(items)
    assert "user:private-password" not in repr(items)


def test_osv_matching_stops_at_expired_deadline(tmp_path: Path) -> None:
    import time

    from xray.analyzers.dependencies import _load_osv_exact_matches

    osv = tmp_path / "osv.json"
    osv.write_text(
        json.dumps({
            "vulns": [{
                "id": "XRAY-TEST-1",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "sample"},
                    "versions": ["1.0"],
                }],
            }],
        }),
        encoding="utf-8",
    )
    matches, complete = _load_osv_exact_matches(
        osv, 1_000_000, deadline=time.monotonic() - 1
    )

    assert matches == {}
    assert complete is False


def test_dependency_analysis_reports_expired_scan_budget(tmp_path: Path) -> None:
    import time

    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["sample==1.0"]\n',
        encoding="utf-8",
    )
    _items, _nodes, _edges, _findings, summary = analyze_dependencies(
        tmp_path, deadline=time.monotonic() - 1
    )

    assert summary["status"] == "partial"
    assert summary["deadline_reached"] is True
