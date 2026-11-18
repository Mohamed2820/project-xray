"""Explicit Architecture Decision Record (ADR) inventory with credential redaction."""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

from xray.analyzers.safe_io import read_project_text
from xray.analyzers.secrets import redact_sensitive_text

def _redact(text: str) -> str:
    """Use the shared credential redactor so analyzer output cannot diverge."""
    return redact_sensitive_text(text)


def analyze_decisions(
    root: Path,
    file_records: list[dict[str, Any]],
    max_bytes: int = 1_000_000,
    *,
    max_records: int = 100,
    deadline: float | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Extract explicit ADR fields without exposing credential-like content."""
    decisions: list[dict[str, Any]] = []
    considered = 0
    stopped = False
    for record in file_records:
        if (deadline is not None and time.monotonic() >= deadline) or len(decisions) >= max_records:
            stopped = True
            break
        path = str(record.get("path", ""))
        name = Path(path).name
        lower = path.lower()
        in_decision_area = (
            lower.startswith(("docs/decisions/", "docs/adr/", "adr/"))
            or ("/" not in path and name.upper().startswith("ADR-"))
            or (lower.startswith("docs/") and name.lower().startswith("adr-"))
        )
        if not in_decision_area or Path(path).suffix.lower() not in {".md", ".markdown"}:
            continue
        text = read_project_text(root, path, max_bytes)
        if text is None:
            continue
        considered += 1
        title_match = re.search(r"(?m)^#\s+(.+?)\s*$", text)
        status_match = re.search(r"(?im)^\s*(?:status|الحالة)\s*:\s*(.+?)\s*$", text)
        sections: dict[str, str] = {}
        matches = list(re.finditer(
            r"(?im)^#{1,4}\s*(context|decision|consequences|alternatives|rationale|"
            r"السياق|القرار|النتائج|البدائل|المبررات)\s*$", text
        ))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            key = match.group(1).lower()
            sections[key] = _redact(text[match.end():end].strip()[:4000])
        context = sections.get("context", sections.get("السياق", ""))
        decision = sections.get("decision", sections.get("القرار", ""))
        consequences = sections.get("consequences", sections.get("النتائج", ""))
        alternatives = sections.get("alternatives", sections.get("البدائل", ""))
        rationale = sections.get("rationale", sections.get("المبررات", ""))
        complete = bool(context and decision and consequences)
        decisions.append({
            "path": path,
            "title": _redact(title_match.group(1)) if title_match else Path(path).stem,
            "status": _redact(status_match.group(1).strip()) if status_match else "unspecified",
            "context_documented": bool(context),
            "decision_documented": bool(decision),
            "consequences_documented": bool(consequences),
            "alternatives_documented": bool(alternatives),
            "rationale_documented": bool(rationale),
            "complete": complete,
            "section_hashes": {
                "context": (
                    hashlib.sha256(context.encode("utf-8")).hexdigest()
                    if context else None
                ),
                "decision": (
                    hashlib.sha256(decision.encode("utf-8")).hexdigest()
                    if decision else None
                ),
                "consequences": (
                    hashlib.sha256(consequences.encode("utf-8")).hexdigest()
                    if consequences else None
                ),
            },
            "context": context,
            "decision": decision,
            "consequences": consequences,
            "alternatives": alternatives,
            "rationale": rationale,
        })
    summary = {
        "status": "partial" if stopped else "analyzed",
        "max_records": max_records,
        "records_found": len(decisions),
        "complete_records": sum(bool(item["complete"]) for item in decisions),
        "incomplete_records": sum(not item["complete"] for item in decisions),
        "files_considered": considered,
        "credential_redaction": True,
        "limitations": [
            "Only explicit Markdown ADR files in recognized locations are inventoried.",
            "Decisions inferred from source code or commit messages are not "
            "treated as documented decisions.",
        ],
    }
    return decisions, summary
