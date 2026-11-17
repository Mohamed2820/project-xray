from pathlib import Path

from xray.analyzers.decisions import analyze_decisions


def test_adr_is_extracted_and_credentials_redacted(tmp_path: Path) -> None:
    decision = tmp_path / "docs" / "decisions" / "ADR-0001.md"
    decision.parent.mkdir(parents=True)
    decision.write_text(
        "# ADR-0001: Storage\n\nStatus: Accepted\n\n"
        "## Context\nNeed storage. API_KEY=verysecretvalue123\n\n"
        "## Decision\nUse SQLite. Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\n\n"
        "## Consequences\nLocal history is available.\n",
        encoding="utf-8",
    )
    records, summary = analyze_decisions(
        tmp_path, [{"path": "docs/decisions/ADR-0001.md"}]
    )
    assert summary["complete_records"] == 1
    assert records[0]["status"] == "Accepted"
    assert records[0]["complete"] is True
    serialized = repr(records)
    assert "verysecretvalue123" not in serialized
    assert "abcdefghijklmnopqrstuvwxyz123456" not in serialized
    assert "deploy-secret" not in serialized
    assert "url-secret-value" not in serialized
    assert records[0]["section_hashes"]["decision"]


def test_adr_scan_is_bounded(tmp_path: Path) -> None:
    folder = tmp_path / "docs" / "adr"
    folder.mkdir(parents=True)
    for index in range(3):
        (folder / f"ADR-{index}.md").write_text(
            "# Decision\n\n## Context\nx\n", encoding="utf-8"
        )
    records, summary = analyze_decisions(
        tmp_path,
        [{"path": f"docs/adr/ADR-{index}.md"} for index in range(3)],
        max_records=2,
    )
    assert len(records) == 2
    assert summary["status"] == "partial"
