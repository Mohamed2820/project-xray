from pathlib import Path

import pytest

from xray.analyzers.safe_io import read_project_bytes, read_project_text


def test_read_project_text_rejects_parent_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("outside-private-content", encoding="utf-8")
    (root / "vendor-link").symlink_to(outside, target_is_directory=True)

    assert read_project_text(root, "vendor-link/secret.txt", 1024) is None
    assert read_project_bytes(root, "../outside/secret.txt", 1024) is None


def test_read_project_text_accepts_regular_in_root_files(tmp_path: Path) -> None:
    root = tmp_path / "project"
    nested = root / "src"
    nested.mkdir(parents=True)
    source = nested / "module.py"
    source.write_text("print('safe')", encoding="utf-8")

    assert read_project_text(root, "src/module.py", 1024) == "print('safe')"
    assert read_project_bytes(root, "src/module.py", 4) is None


def test_read_project_bytes_rejects_final_symlink(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (root / "alias.txt").symlink_to(outside)

    assert read_project_bytes(root, "alias.txt", 1024) is None


@pytest.mark.parametrize(
    "relative_path",
    [
        r"..\\outside.txt",
        r"folder\\..\\outside.txt",
        r"C:\\Windows\\win.ini",
        r"\\\\server\\share\\secret.txt",
    ],
)
def test_rejects_windows_path_traversal_on_all_platforms(
    tmp_path: Path, relative_path: str
) -> None:
    from xray.analyzers.safe_io import read_project_bytes

    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("must-not-be-read", encoding="utf-8")

    assert read_project_bytes(root, relative_path, 1024) is None
