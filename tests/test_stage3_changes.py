from xray.analyzers.changes import compare_snapshots


def _node(identifier: str, kind: str, name: str, path: str) -> dict:
    return {
        "id": identifier, "kind": kind, "name": name,
        "path": path, "line": 1, "metadata": {},
    }


def test_snapshot_diff_detects_add_modify_delete_and_impact() -> None:
    previous = {
        "scan_id": "old",
        "files": [
            {"path": "app.py", "sha256": "old-hash"},
            {"path": "gone.py", "sha256": "gone-hash"},
        ],
        "nodes": [
            _node("file:app.py", "file", "app.py", "app.py"),
            _node("function:app.py:1:run", "function", "run", "app.py"),
            _node("file:gone.py", "file", "gone.py", "gone.py"),
            _node("function:gone.py:1:stop", "function", "stop", "gone.py"),
        ],
        "edges": [],
    }
    current = {
        "scan_id": "new",
        "files": [
            {"path": "app.py", "sha256": "new-hash"},
            {"path": "new.py", "sha256": "new-file-hash"},
        ],
        "nodes": [
            _node("file:app.py", "file", "app.py", "app.py"),
            _node("function:app.py:1:run", "function", "run", "app.py"),
            _node("file:new.py", "file", "new.py", "new.py"),
            _node("function:new.py:1:start", "function", "start", "new.py"),
        ],
        "edges": [{
            "source": "file:app.py", "target": "function:app.py:1:run",
            "relation": "contains",
            "evidence": {"path": "app.py", "line": 1, "detail": ""},
        }, {
            "source": "file:new.py", "target": "function:new.py:1:start",
            "relation": "contains",
            "evidence": {"path": "new.py", "line": 1, "detail": ""},
        }],
    }
    diff = compare_snapshots(current, previous)
    assert diff["status"] == "compared"
    assert [item["path"] for item in diff["modified"]] == ["app.py"]
    assert [item["path"] for item in diff["added"]] == ["new.py"]
    assert [item["path"] for item in diff["deleted"]] == ["gone.py"]
    assert diff["modified"][0]["affected_components"][0]["name"] == "run"
    assert diff["deleted"][0]["affected_components"][0]["name"] == "stop"


def test_diff_refuses_incomplete_hash_baseline() -> None:
    current = {"files": [{"path": "a.py", "sha256": "new"}], "nodes": [], "edges": []}
    previous = {"scan_id": "old", "files": [{"path": "a.py", "sha256": None}]}
    assert compare_snapshots(current, previous)["status"] == "previous_snapshot_without_hashes"


def test_diff_refuses_current_incomplete_hashes() -> None:
    current = {"files": [{"path": "a.py", "sha256": None}], "nodes": [], "edges": []}
    previous = {"scan_id": "old", "files": [{"path": "a.py", "sha256": "old"}]}
    assert compare_snapshots(current, previous)["status"] == "current_snapshot_with_missing_hashes"
