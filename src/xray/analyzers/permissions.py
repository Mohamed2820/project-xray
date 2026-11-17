"""Static inspection of declared Android, CI, and container privileges."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from xray.analyzers.safe_io import read_project_text
from xray.core.models import Evidence, Finding, Node

ANDROID_PERMISSION_LEVELS = {
    "android.permission.INTERNET": ("normal", "low"),
    "android.permission.ACCESS_NETWORK_STATE": ("normal", "low"),
    "android.permission.CAMERA": ("dangerous", "high"),
    "android.permission.RECORD_AUDIO": ("dangerous", "high"),
    "android.permission.ACCESS_FINE_LOCATION": ("dangerous", "high"),
    "android.permission.ACCESS_COARSE_LOCATION": ("dangerous", "medium"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("special", "high"),
    "android.permission.READ_CONTACTS": ("dangerous", "high"),
    "android.permission.WRITE_CONTACTS": ("dangerous", "high"),
    "android.permission.READ_CALENDAR": ("dangerous", "medium"),
    "android.permission.WRITE_CALENDAR": ("dangerous", "medium"),
    "android.permission.READ_SMS": ("dangerous", "critical"),
    "android.permission.RECEIVE_SMS": ("dangerous", "critical"),
    "android.permission.SEND_SMS": ("dangerous", "critical"),
    "android.permission.READ_CALL_LOG": ("dangerous", "critical"),
    "android.permission.WRITE_CALL_LOG": ("dangerous", "critical"),
    "android.permission.CALL_PHONE": ("dangerous", "high"),
    "android.permission.READ_PHONE_STATE": ("dangerous", "high"),
    "android.permission.READ_EXTERNAL_STORAGE": ("dangerous", "medium"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("dangerous", "high"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("special", "critical"),
    "android.permission.READ_MEDIA_IMAGES": ("dangerous", "medium"),
    "android.permission.READ_MEDIA_VIDEO": ("dangerous", "medium"),
    "android.permission.READ_MEDIA_AUDIO": ("dangerous", "medium"),
    "android.permission.POST_NOTIFICATIONS": ("dangerous", "low"),
    "android.permission.BODY_SENSORS": ("dangerous", "high"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("special", "high"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("special", "high"),
    "android.permission.PACKAGE_USAGE_STATS": ("special", "high"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("special", "critical"),
    "android.permission.BLUETOOTH_CONNECT": ("dangerous", "medium"),
    "android.permission.NEARBY_WIFI_DEVICES": ("dangerous", "medium"),
}


def _finding(
    rule: str,
    severity: str,
    message: str,
    path: str,
    detail: str,
    line: int | None = None,
) -> Finding:
    return Finding(rule, severity, message, Evidence(path, line, detail))


def _android_manifest(
    root: Path,
    path: str,
    max_bytes: int,
) -> tuple[list[dict[str, Any]], list[Finding]]:
    text = read_project_text(root, path, max_bytes)
    if text is None:
        return [], []
    cleaned = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    if not re.search(r"<\s*manifest\b", cleaned, re.IGNORECASE) or not re.search(
        r"</\s*manifest\s*>", cleaned, re.IGNORECASE
    ):
        return [], [_finding(
            "permission_android_manifest_parse_error",
            "medium",
            "Android manifest could not be parsed; permission coverage is incomplete.",
            path,
            "Missing or malformed manifest root element.",
        )]

    records: list[dict[str, Any]] = []
    findings: list[Finding] = []
    tags = re.finditer(
        r"<\s*uses-permission(?:-sdk-23|-sdk-m)?\b([^>]*)>",
        cleaned,
        re.IGNORECASE | re.DOTALL,
    )
    last_offset = 0
    line_number = 1
    for index, match in enumerate(tags):
        if index >= 5_000:
            findings.append(_finding(
                "permission_android_manifest_limit",
                "medium",
                "Android manifest permission count exceeded the analysis limit.",
                path,
                "Maximum 5000 permission declarations.",
            ))
            break
        line_number += cleaned.count("\n", last_offset, match.start())
        last_offset = match.start()
        attributes = match.group(1)
        name_match = re.search(
            r"""(?:[A-Za-z_][\w.-]*:)?name\s*=\s*(["'])(.*?)\1""",
            attributes,
            re.IGNORECASE | re.DOTALL,
        )
        if not name_match:
            continue
        name = name_match.group(2).strip()
        max_sdk_match = re.search(
            r"""(?:[A-Za-z_][\w.-]*:)?maxSdkVersion\s*=\s*(["'])(.*?)\1""",
            attributes,
            re.IGNORECASE,
        )
        level, severity = ANDROID_PERMISSION_LEVELS.get(name, ("unknown", "info"))
        records.append({
            "type": "android_permission",
            "name": name,
            "protection_level": level,
            "severity": severity,
            "state": "declared_not_runtime_grant",
            "max_sdk_version": max_sdk_match.group(2) if max_sdk_match else None,
            "source": path,
            "line": line_number,
        })
        if severity in {"medium", "high", "critical"}:
            findings.append(_finding(
                f"android_permission_{level}",
                severity,
                "Manifest declares a permission that can access sensitive device or user data.",
                path,
                name,
                line_number,
            ))
    return records, findings


def _workflow_permissions(
    path: str,
    text: str,
) -> tuple[list[dict[str, Any]], list[Finding]]:
    records: list[dict[str, Any]] = []
    findings: list[Finding] = []
    lines = text.splitlines()
    uses_lines: list[tuple[str, str, bool, int]] = []

    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)permissions\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        indent = len(match.group(1))
        inline = match.group(2).strip()
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                break
            end += 1
        if inline:
            access = inline.strip("'\"")
            records.append({
                "type": "github_actions_permission",
                "scope": "all",
                "access": access,
                "source": path,
                "line": index + 1,
            })
            if access in {"write-all", "admin"}:
                findings.append(_finding(
                    "ci_broad_write_permissions",
                    "high",
                    "Workflow grants broad write permissions.",
                    path,
                    access,
                    index + 1,
                ))
            continue
        for position in range(index + 1, end):
            scope = re.match(
                r"^\s+([A-Za-z0-9_-]+)\s*:\s*([A-Za-z]+)\s*$",
                lines[position],
            )
            if not scope:
                continue
            name, access = scope.group(1), scope.group(2).lower()
            records.append({
                "type": "github_actions_permission",
                "scope": name,
                "access": access,
                "source": path,
                "line": position + 1,
            })
            if access in {"write", "admin"}:
                findings.append(_finding(
                    "ci_write_permission",
                    "medium",
                    "Workflow token has write access; verify the minimum required scope.",
                    path,
                    f"{name}: {access}",
                    position + 1,
                ))

    for number, line in enumerate(lines, start=1):
        match = re.match(
            r"""^\s*(?:-\s*)?uses\s*:\s*['"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^'"\s]+)""",
            line,
        )
        if not match:
            continue
        action, reference = match.groups()
        pinned = bool(re.fullmatch(r"[0-9a-fA-F]{40}", reference))
        uses_lines.append((action, reference, pinned, number))
        records.append({
            "type": "github_action_reference",
            "action": action,
            "reference": reference,
            "immutable_sha_pinned": pinned,
            "source": path,
            "line": number,
        })
        if not pinned:
            findings.append(_finding(
                "ci_action_not_sha_pinned",
                "medium",
                "GitHub Action uses a mutable tag or branch instead of a full commit SHA.",
                path,
                f"{action}@{reference}",
                number,
            ))

    is_target = bool(re.search(
        r"^\s*pull_request_target\s*:",
        text,
        re.MULTILINE,
    ))
    has_write = any(
        item.get("type") == "github_actions_permission"
        and item.get("access") in {"write", "admin", "write-all"}
        for item in records
    )
    has_checkout = any(
        action == "actions/checkout" for action, _, _, _ in uses_lines
    )
    if is_target and has_write and has_checkout:
        findings.append(_finding(
            "ci_pull_request_target_write_checkout",
            "high",
            "Privileged pull_request_target workflow combines write permissions "
            "with checkout; review untrusted PR code exposure.",
            path,
            "pull_request_target + write permission + actions/checkout",
        ))
    if "secrets: inherit" in text.lower():
        findings.append(_finding(
            "ci_inherited_secrets",
            "medium",
            "Workflow inherits all available secrets; pass only required secrets.",
            path,
            "secrets: inherit",
        ))
    return records, findings


def _deployment_config(
    path: str,
    text: str,
) -> tuple[list[dict[str, Any]], list[Finding]]:
    records: list[dict[str, Any]] = []
    findings: list[Finding] = []

    def add(rule: str, severity: str, message: str, detail: str) -> None:
        records.append({
            "type": "deployment_security_setting",
            "setting": rule,
            "severity": severity,
            "value": detail,
            "source": path,
        })
        findings.append(_finding(rule, severity, message, path, detail))

    if Path(path).name.lower() == "dockerfile":
        if re.search(r"(?im)^\s*USER\s+(?:root|0)(?::\d+)?\s*(?:#.*)?$", text):
            add(
                "container_runs_as_root",
                "high",
                "Dockerfile explicitly switches to root; prefer a dedicated non-root user.",
                "USER root",
            )
        elif not re.search(r"(?im)^\s*USER\s+\S+", text):
            add(
                "container_user_not_declared",
                "medium",
                "Dockerfile does not declare a non-root USER; the base image default is unknown.",
                "No USER instruction found",
            )
        if re.search(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)", text):
            add(
                "container_remote_script_pipe",
                "high",
                "Dockerfile pipes a downloaded script directly to a shell.",
                "curl or wget piped to sh/bash",
            )
        if re.search(r"(?im)^\s*ADD\s+https?://", text):
            add(
                "container_remote_add",
                "medium",
                "Dockerfile downloads a remote resource with ADD; verify integrity and provenance.",
                "ADD with HTTP(S) source",
            )

    if re.search(r"(?im)^\s*privileged\s*:\s*true\b", text):
        add(
            "container_privileged_mode",
            "critical",
            "Container configuration enables privileged mode.",
            "privileged: true",
        )
    if re.search(r"(?im)^\s*hostpath\s*:", text):
        add(
            "container_host_path_mount",
            "high",
            "Configuration mounts a host filesystem path into a workload.",
            "hostPath mount",
        )
    if re.search(r"(?im)^\s*host(?:network|pid|ipc)\s*:\s*true\b", text):
        add(
            "container_host_namespace",
            "high",
            "Workload shares a host namespace, increasing host exposure.",
            "hostNetwork/hostPID/hostIPC: true",
        )
    if re.search(r"(?im)^\s*allowPrivilegeEscalation\s*:\s*true\b", text):
        add(
            "container_privilege_escalation",
            "high",
            "Container allows privilege escalation.",
            "allowPrivilegeEscalation: true",
        )
    if re.search(r"(?im)^\s*runAsNonRoot\s*:\s*false\b", text):
        add(
            "container_nonroot_disabled",
            "high",
            "Container security context explicitly permits root execution.",
            "runAsNonRoot: false",
        )
    if re.search(r"(?im)^\s*capabilities\s*:", text) and re.search(
        r"(?im)^\s*-\s*(?:SYS_ADMIN|SYS_PTRACE|NET_ADMIN|ALL)\s*$",
        text,
    ):
        add(
            "container_dangerous_capability",
            "high",
            "Container requests a powerful Linux capability.",
            "SYS_ADMIN/SYS_PTRACE/NET_ADMIN/ALL",
        )
    return records, findings


def analyze_permissions(
    root: Path,
    file_records: list[dict[str, Any]],
    max_bytes: int = 1_000_000,
    *,
    deadline: float | None = None,
    max_config_files: int = 500,
) -> tuple[list[dict[str, Any]], list[Node], list[Finding], dict[str, Any]]:
    """Inspect known permission-bearing files with an explicit file-count/time budget."""
    permissions: list[dict[str, Any]] = []
    nodes: list[Node] = []
    findings: list[Finding] = []
    analyzed_files: list[str] = []
    stopped = False
    for record in file_records:
        if (
            (deadline is not None and time.monotonic() >= deadline)
            or len(analyzed_files) >= max_config_files
        ):
            stopped = True
            break
        path = str(record.get("path", ""))
        lower = path.lower()
        suffix = Path(path).suffix.lower()
        content: str | None = None
        if Path(path).name == "AndroidManifest.xml" or (
            suffix == ".xml" and "manifest" in Path(path).name.lower()
        ):
            found, issues = _android_manifest(root, path, max_bytes)
            permissions.extend(found)
            findings.extend(issues)
            analyzed_files.append(path)
        elif lower.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
            content = read_project_text(root, path, max_bytes)
            if content is not None:
                found, issues = _workflow_permissions(path, content)
                permissions.extend(found)
                findings.extend(issues)
                analyzed_files.append(path)
        elif Path(path).name.lower() == "dockerfile" or (
            suffix in {".yml", ".yaml"} and any(
                token in lower
                for token in ("k8s", "kubernetes", "deployment", "compose")
            )
        ):
            content = read_project_text(root, path, max_bytes)
            if content is not None:
                found, issues = _deployment_config(path, content)
                permissions.extend(found)
                findings.extend(issues)
                analyzed_files.append(path)

    for index, item in enumerate(permissions):
        identifier = (
            "permission:"
            f"{index}:{item.get('type')}:"
            f"{item.get('name', item.get('scope', item.get('setting', 'unknown')))}"
        )
        nodes.append(Node(
            identifier,
            "permission",
            str(item.get("name", item.get("scope", item.get("setting", "permission")))),
            str(item.get("source", "")),
            item.get("line"),
            {
                key: value for key, value in item.items()
                if key not in {"source", "line", "name", "scope", "setting"}
            },
        ))
    summary = {
        "status": "partial" if stopped else "analyzed",
        "max_config_files": max_config_files,
        "items_found": len(permissions),
        "files_analyzed": analyzed_files,
        "high_or_critical_findings": sum(
            finding.severity in {"high", "critical"} for finding in findings
        ),
        "limitations": [
            "Android declarations are not proof that a user granted the permission "
            "or that code used it.",
            "Text-based workflow and deployment checks are heuristic and do not "
            "fully parse every YAML dialect.",
            "Unknown or generated configuration formats may be missed.",
        ],
    }
    return permissions, nodes, findings, summary
