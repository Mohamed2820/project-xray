"""Safe, bounded file access for paths inside a scanned project."""
from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO


def _validated_parts(relative_path: str) -> tuple[str, ...] | None:
    # X-Ray paths are canonical POSIX-relative paths. Reject Windows separators
    # and drive-qualified forms too, even when running on POSIX, so an artifact
    # created on one platform cannot become traversal on another.
    relative = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if (
        "\\\\" in relative_path
        or "\\x00" in relative_path
        or windows.is_absolute()
        or bool(windows.drive)
        or relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or any(part in {"", "."} for part in relative.parts)
        or (os.name == "nt" and any(":" in part for part in relative.parts))
    ):
        return None
    return relative.parts


def _open_beneath(root_path: Path, parts: tuple[str, ...]) -> int:
    """Open a file beneath root using directory descriptors where supported."""
    base_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)

    if os.open in getattr(os, "supports_dir_fd", set()) and directory_flag:
        root_fd = os.open(root_path, base_flags | directory_flag | nofollow)
        current_fd = root_fd
        try:
            for component in parts[:-1]:
                next_fd = os.open(
                    component,
                    base_flags | directory_flag | nofollow,
                    dir_fd=current_fd,
                )
                if current_fd != root_fd:
                    os.close(current_fd)
                current_fd = next_fd
            return os.open(parts[-1], base_flags | nofollow, dir_fd=current_fd)
        finally:
            if current_fd != root_fd:
                os.close(current_fd)
            os.close(root_fd)

    candidate = root_path
    for component in parts:
        candidate = candidate / component
        if candidate.is_symlink():
            raise OSError("Symbolic links are not allowed in scanned project paths.")
    try:
        candidate.resolve(strict=True).relative_to(root_path)
    except (OSError, RuntimeError, ValueError):
        raise OSError("Path escaped the project root.") from None
    return os.open(candidate, base_flags | nofollow)


def open_project_file(root: Path, relative_path: str) -> BinaryIO | None:
    """Open a regular file under root without following symlink components."""
    parts = _validated_parts(relative_path)
    if parts is None:
        return None
    handle: BinaryIO | None = None
    try:
        root_path = root.resolve(strict=True)
        descriptor = _open_beneath(root_path, parts)
        handle = os.fdopen(descriptor, "rb")
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            handle.close()
            return None
        return handle
    except (OSError, RuntimeError, ValueError):
        if handle is not None:
            handle.close()
        return None


def read_project_bytes(root: Path, relative_path: str, max_bytes: int) -> bytes | None:
    """Read a regular file beneath root without following symlink components."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    handle = open_project_file(root, relative_path)
    if handle is None:
        return None
    with handle:
        if os.fstat(handle.fileno()).st_size > max_bytes:
            return None
        content = handle.read(max_bytes + 1)
    return content if len(content) <= max_bytes else None


def read_project_text(root: Path, relative_path: str, max_bytes: int) -> str | None:
    content = read_project_bytes(root, relative_path, max_bytes)
    if content is None:
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None
