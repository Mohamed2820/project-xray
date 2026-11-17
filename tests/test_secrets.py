from pathlib import Path

import pytest

from xray.analyzers.secrets import scan_secrets


def test_secret_value_is_never_returned(tmp_path: Path) -> None:
    value = "supersecretvalue123"
    source = tmp_path / "settings.py"
    source.write_text(f"API_KEY = '{value}'", encoding="utf-8")
    findings = scan_secrets(source, "settings.py")
    assert len(findings) == 1
    assert value not in repr(findings)
    assert findings[0].evidence.line == 1


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        ("ghp_" + "A" * 36, "github_token"),
        ("AKIA" + "A" * 16, "aws_access_key_id"),
        ("sk_live_" + "a" * 24, "stripe_secret_key"),
        ("AIza" + "A" * 35, "google_api_key"),
        ("xoxb-" + "A" * 24, "slack_token"),
        ('{"api_key": "jsonsecretvalue123"}', "sensitive_assignment"),
        ("AWS_SECRET_ACCESS_KEY=awssecretvalue123", "sensitive_assignment"),
        ("GITHUB_TOKEN=genericgithubsecret123", "sensitive_assignment"),
        ("STRIPE_SECRET_KEY=genericstripesecret123", "sensitive_assignment"),
        ("client_secret: yamlsecretvalue123", "sensitive_assignment"),
    ],
)
def test_detects_common_credential_formats_without_returning_values(
    tmp_path: Path, line: str, rule: str
) -> None:
    source = tmp_path / "secrets.txt"
    source.write_text(line, encoding="utf-8")
    findings = scan_secrets(source, "secrets.txt")
    assert any(item.rule_id == rule for item in findings)
    assert line not in repr(findings)


def test_obvious_placeholders_are_not_reported(tmp_path: Path) -> None:
    source = tmp_path / "example.env"
    source.write_text(
        'API_KEY="your_api_key_here"\nSECRET="${SECRET}"\n',
        encoding="utf-8",
    )
    assert scan_secrets(source, "example.env") == []


def test_scanner_refuses_oversized_file(tmp_path: Path) -> None:
    source = tmp_path / "large.txt"
    source.write_text("API_KEY=" + "a" * 100, encoding="utf-8")
    assert scan_secrets(source, "large.txt", max_bytes=16) == []


def test_scanner_does_not_follow_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("API_KEY=supersecretvalue123", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    assert scan_secrets(link, "link.txt") == []



@pytest.mark.parametrize(
    "value",
    [
        "sk-proj-" + "A" * 40,
        "eyJ" + "A" * 20 + "." + "B" * 20 + "." + "C" * 20,
    ],
)
def test_detects_additional_token_shapes_and_redacts_values(
    tmp_path: Path, value: str
) -> None:
    source = tmp_path / "credential.env"
    source.write_text(f"TOKEN={value}", encoding="utf-8")
    findings = scan_secrets(source, "credential.env")
    assert findings
    assert value not in repr(findings)


def test_detects_bearer_authorization_header(tmp_path: Path) -> None:
    token = "BearerSecretTokenValue123456"
    source = tmp_path / "headers.txt"
    source.write_text(f"Authorization: Bearer {token}", encoding="utf-8")
    findings = scan_secrets(source, "headers.txt")
    assert findings
    assert token not in repr(findings)



def test_repeated_character_secret_is_not_silently_treated_as_placeholder(
    tmp_path: Path,
) -> None:
    value = "A" * 32
    source = tmp_path / "settings.env"
    source.write_text(f"API_KEY={value}", encoding="utf-8")
    findings = scan_secrets(source, "settings.env")
    assert findings
    assert value not in repr(findings)
