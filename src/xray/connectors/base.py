"""Connector contracts shared by local and future remote project sources."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable


@dataclass(frozen=True)
class FileEntry:
    """A single regular file exposed by a project connector."""

    path: Path
    relative_path: str
    size_bytes: int


@runtime_checkable
class ProjectConnector(Protocol):
    """Read-only source of project files."""

    @property
    def root(self) -> Path: ...

    def iter_files(self) -> Iterator[FileEntry]: ...
