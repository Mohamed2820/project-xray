"""Read-only local filesystem connector with bounded, no-symlink traversal."""
from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

from xray.connectors.base import FileEntry

DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".nox", "build", "dist", "coverage", ".next",
})
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_MAX_DEPTH = 64


class LocalFilesystemConnector:
    """Expose regular files without following symlinks or changing the source."""

    def __init__(
        self,
        root: str | Path,
        excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        if max_depth < 0:
            raise ValueError("max_depth must not be negative")
        requested_root = Path(root).expanduser()
        if requested_root.is_symlink():
            raise ValueError("Project root must not be a symbolic link.")
        self._root = requested_root.resolve()
        if not self._root.is_dir():
            raise NotADirectoryError(self._root)
        self.excluded_dirs = excluded_dirs
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.errors: list[dict[str, str]] = []
        self.limit_reached: str | None = None
        self.visited_entries = 0

    @property
    def root(self) -> Path:
        return self._root

    def _record_error(self, error: OSError) -> None:
        filename = getattr(error, "filename", None)
        self.errors.append({
            "path": str(filename) if filename else str(self._root),
            "error": type(error).__name__,
        })

    def iter_files(self) -> Iterator[FileEntry]:
        """Stream entries with bounded traversal; do not follow directory links."""
        self.errors.clear()
        self.limit_reached = None
        self.visited_entries = 0
        pending: list[tuple[Path, int]] = [(self._root, 0)]
        while pending:
            current_path, depth = pending.pop()
            child_directories: list[Path] = []
            try:
                with os.scandir(current_path) as entries:
                    for entry in entries:
                        self.visited_entries += 1
                        if self.visited_entries > self.max_entries:
                            self.limit_reached = "max_entries"
                            return
                        if entry.name in self.excluded_dirs:
                            continue
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if depth >= self.max_depth:
                                    self.limit_reached = "max_depth"
                                    continue
                                child_directories.append(Path(entry.path))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            metadata = entry.stat(follow_symlinks=False)
                            if not stat.S_ISREG(metadata.st_mode):
                                continue
                            path = Path(entry.path)
                            relative = path.relative_to(self._root).as_posix()
                            yield FileEntry(path, relative, metadata.st_size)
                        except OSError as error:
                            self._record_error(error)
            except OSError as error:
                self._record_error(error)
            pending.extend(
                (directory, depth + 1)
                for directory in reversed(sorted(child_directories, key=lambda item: item.name))
            )
