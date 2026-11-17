"""Typed, serializable data models shared by the X-Ray engine."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class Evidence:
    path: str
    line: int | None = None
    detail: str = ""


@dataclass
class Node:
    id: str
    kind: str
    name: str
    path: str
    line: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    relation: str
    evidence: Evidence


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    evidence: Evidence


@dataclass
class ScanReport:
    schema_version: str = "1.2"
    root: str = ""
    scan_id: str = field(default_factory=lambda: uuid4().hex)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    files: list[dict[str, Any]] = field(default_factory=list)
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    analyses: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
