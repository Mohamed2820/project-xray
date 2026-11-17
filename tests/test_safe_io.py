from pathlib import Path

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
