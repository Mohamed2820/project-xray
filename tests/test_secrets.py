from pathlib import Path

from xray.analyzers.secrets import scan_secrets


def test_secret_value_is_never_returned(tmp_path: Path) -> None:
    value = "supersecretvalue123"
    source = tmp_path / "settings.py"
    source.write_text(f"API_KEY = '{value}'")
    findings = scan_secrets(source, "settings.py")
    assert len(findings) == 1
    assert value not in repr(findings)
    assert findings[0].evidence.line == 1
