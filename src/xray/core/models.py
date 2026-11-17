"""Typed, serializable data models used by analyzers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


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
    schema_version: str = "1.0"
    root: str = ""
    files: list[dict[str, Any]] = field(default_factory=list)
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
