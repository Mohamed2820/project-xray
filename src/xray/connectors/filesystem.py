"""Read-only local filesystem connector with conservative traversal rules."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterator

from xray.connectors.base import FileEntry

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        ".tox", ".nox", "build", "dist", "coverage", ".next",
    }
)


class LocalFilesystemConnector:
    """Expose regular files without following symlinks or changing the source."""

    def __init__(
        self,
        root: str | Path,
        excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
    ) -> None:
        requested_root = Path(root).expanduser()
        if requested_root.is_symlink():
            raise ValueError("Project root must not be a symbolic link.")
        self._root = requested_root.resolve()
        if not self._root.is_dir():
            raise NotADirectoryError(self._root)
        self.excluded_dirs = excluded_dirs
        self.errors: list[dict[str, str]] = []

    @property
    def root(self) -> Path:
        return self._root

    def _record_error(self, error: OSError) -> None:
        filename = getattr(error, "filename", None)
        self.errors.append(
            {
                "path": str(filename) if filename else str(self._root),
                "error": type(error).__name__,
            }
        )

    def iter_files(self) -> Iterator[FileEntry]:
        """Yield deterministic file entries; unreadable paths are recorded."""
        self.errors.clear()
        for current, directories, filenames in os.walk(
            self._root,
            topdown=True,
            onerror=self._record_error,
            followlinks=False,
        ):
            current_path = Path(current)
            directories[:] = sorted(
                name
                for name in directories
                if name not in self.excluded_dirs
                and not (current_path / name).is_symlink()
            )
            for filename in sorted(filenames):
                path = current_path / filename
                try:
                    metadata = path.lstat()
                except OSError as error:
                    self._record_error(error)
                    continue
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    continue
                relative = path.relative_to(self._root).as_posix()
                yield FileEntry(path, relative, metadata.st_size)
