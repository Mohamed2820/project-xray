"""Conservative secret-pattern scanner. Matched values are never returned."""
from __future__ import annotations

import re
from pathlib import Path

from xray.core.models import Evidence, Finding

_KEY_ASSIGNMENT = re.compile(
    r"""(?i)(?:api[_-]?key|access[_-]?token|secret|password)"""
    r"""\s*[:=]\s*['"]?([A-Za-z0-9_./+=-]{8,})"""
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("generic_api_key_assignment", _KEY_ASSIGNMENT),
    ("private_key_header", _PRIVATE_KEY),
)


def scan_secrets(path: Path, relative_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        return findings
    for number, line in enumerate(lines, start=1):
        for rule_id, pattern in PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity="high",
                        message="Potential secret detected; value redacted.",
                        evidence=Evidence(
                            relative_path,
                            number,
                            "Matched content intentionally omitted.",
                        ),
                    )
                )
                break
    return findings
