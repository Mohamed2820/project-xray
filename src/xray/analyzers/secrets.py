"""Bounded secret-pattern scanning. Matched values are never returned."""
from __future__ import annotations
import os
import re
import stat
from pathlib import Path
from xray.core.models import Evidence, Finding
DEFAULT_MAX_BYTES = 1_000_000
_ASSIGNMENT = re.compile(
    r"""(?ix)\b(?P<key>
        api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|
        oauth[_-]?token|client[_-]?secret|secret(?:[_-]?key)?|
        password|passwd|passphrase|private[_-]?key|
        aws[_-]?secret[_-]?access[_-]?key|credential|token
    )\b["']?\s*[:=]\s*["']?(?P<value>[A-Za-z0-9_./+=:@%-]{8,})"""
)
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
)
_PLACEHOLDERS = {"changeme", "change_me", "replace_me", "placeholder", "example", "dummy", "notasecret"}

def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    return (
        normalized in _PLACEHOLDERS
        or normalized.startswith(("your_", "your-", "replace_", "placeholder_"))
        or (len(normalized) >= 8 and len(set(normalized)) == 1)
        or normalized.startswith(("$" + "{", "<"))
    )

def _read_bounded_regular_file(path: Path, max_bytes: int) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                return None
            content = handle.read(max_bytes + 1)
    except (OSError, ValueError):
        return None
    return content if len(content) <= max_bytes else None

def scan_secrets(path: Path, relative_path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> list[Finding]:
    """Return redacted, line-level findings from a bounded regular file."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    content = _read_bounded_regular_file(path, max_bytes)
    if content is None:
        return []
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return []
    findings: list[Finding] = []
    for number, line in enumerate(lines, start=1):
        rule_id: str | None = None
        for candidate, pattern in _PATTERNS:
            if pattern.search(line):
                rule_id = candidate
                break
        if rule_id is None:
            assignment = _ASSIGNMENT.search(line)
            if assignment and not _is_placeholder(assignment.group("value")):
                rule_id = "sensitive_assignment"
        if rule_id:
            findings.append(Finding(
                rule_id=rule_id,
                severity="high",
                message="Potential credential detected; matched value redacted.",
                evidence=Evidence(relative_path, number, "Matched content intentionally omitted."),
            ))
    return findings
