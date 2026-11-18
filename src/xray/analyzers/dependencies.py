"""Offline dependency inventory and risk analysis for common package ecosystems."""
from __future__ import annotations

import json
import os
import re
import stat
import time
import tomllib
from pathlib import Path
from typing import Any

from xray.analyzers.safe_io import read_project_text
from xray.core.models import Edge, Evidence, Finding, Node

MAX_DEPENDENCIES = 10_000
MAX_OSV_BYTES = 50 * 1024 * 1024
MAX_OSV_VERSION_RECORDS = 250_000


def _redact_source(source: str) -> str:
    """Remove embedded URL credentials and credential-like query parameters."""
    result = re.sub(
        r"(?i)(https?://)[^/@\s]+@",
        r"\1[REDACTED]@",
        source,
    )
    result = re.sub(
        r"(?i)([?&](?:token|access_token|api_key|password|secret)=)[^&\s]+",
        r"\1[REDACTED]",
        result,
    )
    return result


def _normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirement(value: str) -> tuple[str, str]:
    value = value.split(";", 1)[0].strip()
    match = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)", value)
    return (match.group(1), match.group(2).strip()) if match else ("", "")


def _risk_flags(requested: str, version: str, source: str = "") -> list[str]:
    flags: list[str] = []
    constraint = requested.strip()
    if not version and not constraint:
        flags.append("version_not_declared")
    if "*" in constraint or "latest" in constraint.lower():
        flags.append("wildcard_or_latest_version")
    if constraint and not re.search(r"(?:==|===|~=|\b\d)", constraint):
        flags.append("unbounded_version_constraint")
    elif constraint and not re.match(r"^(?:===|==)[^,*]+$", constraint):
        flags.append("non_exact_version_constraint")
    if (
        source.startswith(("git+", "git://", "https://", "http://"))
        or re.search(r"(?i)(?:git\+|git://|https?://)", constraint)
    ):
        flags.append("external_or_git_source")
    if source.startswith(("file:", "path:")) or constraint.startswith(("file:", "path:")):
        flags.append("local_path_dependency")
    if version.lower() in {"latest", "master", "main", "head"}:
        flags.append("mutable_reference")
    return flags


def _load_json(root: Path, path: str, max_bytes: int) -> dict[str, Any] | None:
    text = read_project_text(root, path, max_bytes)
    if text is None:
        return None
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _load_toml(root: Path, path: str, max_bytes: int) -> dict[str, Any] | None:
    text = read_project_text(root, path, max_bytes)
    if text is None:
        return None
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _python_manifest(root: Path, max_bytes: int) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    data = _load_toml(root, "pyproject.toml", max_bytes)
    if data:
        project = data.get("project", {})
        if isinstance(project, dict):
            required = project.get("dependencies", [])
            if not isinstance(required, list):
                required = []
            for raw in required:
                name, requested = _parse_requirement(str(raw))
                if name:
                    found.append({
                        "ecosystem": "PyPI", "name": name,
                        "requested": requested, "source": "pyproject.toml",
                    })
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group, requirements in optional.items():
                    if isinstance(requirements, list):
                        for raw in requirements:
                            name, requested = _parse_requirement(str(raw))
                            if name:
                                found.append({
                                    "ecosystem": "PyPI", "name": name,
                                    "requested": requested, "source": "pyproject.toml",
                                    "group": str(group),
                                })
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        if isinstance(poetry, dict):
            for section in ("dependencies", "dev-dependencies"):
                values = poetry.get(section, {})
                if isinstance(values, dict):
                    for name, specification in values.items():
                        if str(name).lower() == "python":
                            continue
                        requested = (
                            str(specification.get("version", ""))
                            if isinstance(specification, dict) else str(specification)
                        )
                        found.append({
                            "ecosystem": "PyPI", "name": str(name),
                            "requested": requested, "source": "pyproject.toml",
                        })
    for name in ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt"):
        text = read_project_text(root, name, max_bytes)
        if not text:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith(("-e ", "--editable ")):
                stripped = stripped.split(maxsplit=1)[-1]
            if stripped.startswith("-"):
                continue
            egg = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", stripped)
            if egg and ("git+" in stripped or "https://" in stripped):
                package = egg.group(1)
                requested = stripped
            else:
                package, requested = _parse_requirement(stripped)
            if package:
                found.append({
                    "ecosystem": "PyPI", "name": package,
                    "requested": requested, "source": name,
                })
    return found


def _lock_dependencies(
    root: Path, max_bytes: int, direct: list[dict[str, str]]
) -> list[dict[str, str]]:
    direct_names = {_normal(x["name"]) for x in direct}
    result: list[dict[str, str]] = []

    poetry = _load_toml(root, "poetry.lock", max_bytes)
    uv = _load_toml(root, "uv.lock", max_bytes)
    for path, lock in (("poetry.lock", poetry), ("uv.lock", uv)):
        if lock:
            packages = lock.get("package", lock.get("packages", []))
            if isinstance(packages, list):
                for item in packages[:MAX_DEPENDENCIES]:
                    if isinstance(item, dict) and item.get("name") and item.get("version"):
                        name = str(item["name"])
                        source_data = item.get("source", {})
                        source = (
                            str(source_data.get("url", ""))
                            if isinstance(source_data, dict) else ""
                        )
                        result.append({
                            "ecosystem": "PyPI", "name": name, "version": str(item["version"]),
                            "direct": str(_normal(name) in direct_names).lower(),
                            "source": path, "resolved_source": source,
                        })

    pipfile = _load_json(root, "Pipfile.lock", max_bytes)
    if pipfile:
        for section in ("default", "develop"):
            packages = pipfile.get(section, {})
            if isinstance(packages, dict):
                for name, value in list(packages.items())[:MAX_DEPENDENCIES]:
                    version = value.get("version", "") if isinstance(value, dict) else ""
                    result.append({
                        "ecosystem": "PyPI", "name": str(name), "version": str(version).lstrip("="),
                        "direct": str(_normal(str(name)) in direct_names).lower(),
                        "source": "Pipfile.lock",
                    })

    npm_manifest = _load_json(root, "package.json", max_bytes)
    npm_sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    if npm_manifest:
        for section in npm_sections:
            packages = npm_manifest.get(section, {})
            if isinstance(packages, dict):
                for name, requested in packages.items():
                    result.append({
                        "ecosystem": "npm", "name": str(name), "requested": str(requested),
                        "direct": "true", "source": "package.json",
                        "group": section,
                    })
    package_lock = _load_json(root, "package-lock.json", max_bytes)
    if package_lock:
        packages = package_lock.get("packages", {})
        if isinstance(packages, dict):
            for location, item in list(packages.items())[:MAX_DEPENDENCIES]:
                if not location or not isinstance(item, dict):
                    continue
                name = item.get("name") or location.rsplit("node_modules/", 1)[-1]
                is_direct = (
                    location.count("node_modules/") == 1
                    and location.startswith("node_modules/")
                )
                if name:
                    result.append({
                        "ecosystem": "npm", "name": str(name),
                        "version": str(item.get("version", "")),
                        "direct": str(is_direct).lower(),
                        "source": "package-lock.json",
                        "resolved_source": str(item.get("resolved", "")),
                    })
        else:
            def walk_npm(items: dict[str, Any], depth: int = 0) -> None:
                if depth > 32:
                    return
                for name, item in list(items.items())[:MAX_DEPENDENCIES]:
                    if not isinstance(item, dict):
                        continue
                    direct_item = depth == 0
                    result.append({
                        "ecosystem": "npm", "name": str(name),
                        "version": str(item.get("version", "")),
                        "direct": str(direct_item).lower(),
                        "source": "package-lock.json",
                        "resolved_source": str(item.get("resolved", "")),
                    })
                    nested = item.get("dependencies", {})
                    if isinstance(nested, dict):
                        walk_npm(nested, depth + 1)
            deps = package_lock.get("dependencies", {})
            if isinstance(deps, dict):
                walk_npm(deps)

    cargo = _load_toml(root, "Cargo.toml", max_bytes)
    cargo_names: set[str] = set()
    if cargo:
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            values = cargo.get(section, {})
            if isinstance(values, dict):
                for name, spec in values.items():
                    cargo_names.add(_normal(str(name)))
                    requested = (
                        str(spec.get("version", ""))
                        if isinstance(spec, dict) else str(spec)
                    )
                    result.append({
                        "ecosystem": "crates.io", "name": str(name),
                        "requested": requested, "direct": "true", "source": "Cargo.toml",
                        "resolved_source": (
                            str(spec.get("git", "")) if isinstance(spec, dict) else ""
                        ),
                    })
    cargo_lock = _load_toml(root, "Cargo.lock", max_bytes)
    if cargo_lock and isinstance(cargo_lock.get("package"), list):
        for item in cargo_lock["package"][:MAX_DEPENDENCIES]:
            if isinstance(item, dict) and item.get("name") and item.get("version"):
                result.append({
                    "ecosystem": "crates.io", "name": str(item["name"]),
                    "version": str(item["version"]),
                    "direct": str(_normal(str(item["name"])) in cargo_names).lower(),
                    "source": "Cargo.lock", "resolved_source": str(item.get("source", "")),
                })

    composer = _load_json(root, "composer.json", max_bytes)
    composer_direct: set[str] = set()
    if composer:
        for section in ("require", "require-dev"):
            values = composer.get(section, {})
            if isinstance(values, dict):
                for name, version in values.items():
                    composer_direct.add(str(name).lower())
                    result.append({
                        "ecosystem": "Packagist", "name": str(name),
                        "requested": str(version), "direct": "true",
                        "source": "composer.json", "group": section,
                    })
    composer_lock = _load_json(root, "composer.lock", max_bytes)
    if composer_lock:
        for section in ("packages", "packages-dev"):
            values = composer_lock.get(section, [])
            if isinstance(values, list):
                for item in values[:MAX_DEPENDENCIES]:
                    if isinstance(item, dict) and item.get("name"):
                        result.append({
                            "ecosystem": "Packagist", "name": str(item["name"]),
                            "version": str(item.get("version", "")).lstrip("v"),
                            "direct": str(str(item["name"]).lower() in composer_direct).lower(),
                            "source": "composer.lock",
                        })

    go_mod = read_project_text(root, "go.mod", max_bytes)
    if go_mod:
        in_require_block = False
        for raw in go_mod.splitlines():
            line = raw.strip()
            if line.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and line == ")":
                in_require_block = False
                continue
            is_single_requirement = line.startswith("require ")
            if is_single_requirement:
                line = line[len("require "):]
            elif not in_require_block:
                continue
            if not line or line.startswith("//"):
                continue
            requirement, _, comment = line.partition("//")
            parts = requirement.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                indirect = "indirect" in comment.split()
                result.append({
                    "ecosystem": "Go", "name": parts[0],
                    "version": parts[1], "direct": str(not indirect).lower(),
                    "source": "go.mod",
                })

    pom = read_project_text(root, "pom.xml", max_bytes)
    if pom:
        # Lightweight tag extraction only; never invoke an XML entity/DTD parser.
        for dependency in re.findall(
            r"<(?:[A-Za-z0-9_.-]+:)?dependency\b[^>]*>(.*?)</(?:[A-Za-z0-9_.-]+:)?dependency\s*>",
            pom,
            re.IGNORECASE | re.DOTALL,
        ):
            values: dict[str, str] = {}
            for tag in ("groupId", "artifactId", "version"):
                match = re.search(
                    rf"<(?:[A-Za-z0-9_.-]+:)?{tag}\b[^>]*>(.*?)</(?:[A-Za-z0-9_.-]+:)?{tag}\s*>",
                    dependency,
                    re.IGNORECASE | re.DOTALL,
                )
                if match:
                    values[tag] = re.sub(r"\s+", "", match.group(1))
            group = values.get("groupId", "")
            artifact = values.get("artifactId", "")
            if group and artifact:
                result.append({
                    "ecosystem": "Maven", "name": f"{group}:{artifact}",
                    "requested": values.get("version", ""),
                    "direct": "true", "source": "pom.xml",
                })

    nuget = read_project_text(root, "packages.lock.json", max_bytes)
    if nuget:
        try:
            lock = json.loads(nuget)
            for _project_name, project in lock.items():
                if not isinstance(project, dict):
                    continue
                for name, item in project.items():
                    if isinstance(item, dict):
                        result.append({
                            "ecosystem": "NuGet", "name": str(name),
                            "version": str(item.get("resolved", "")),
                            "direct": str(item.get("type") == "Direct").lower(),
                            "source": "packages.lock.json",
                        })
        except (json.JSONDecodeError, RecursionError):
            pass
    return result[:MAX_DEPENDENCIES]


def _load_osv_exact_matches(
    path: Path | None,
    max_bytes: int,
    *,
    deadline: float | None = None,
) -> tuple[dict[tuple[str, str, str], list[str]], bool]:
    if path is None:
        return {}, True
    descriptor: int | None = None
    try:
        candidate = path.expanduser()
        before = os.lstat(candidate)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            return {}, False
        if before.st_size > MAX_OSV_BYTES:
            return {}, False
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_OSV_BYTES
                or (metadata.st_dev, metadata.st_ino)
                != (before.st_dev, before.st_ino)
            ):
                return {}, False
            raw = handle.read(MAX_OSV_BYTES + 1)
        if len(raw) > MAX_OSV_BYTES:
            return {}, False
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return {}, False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    matches: dict[tuple[str, str, str], list[str]] = {}
    vulnerabilities = data.get("vulns", []) if isinstance(data, dict) else []
    if not isinstance(vulnerabilities, list):
        return matches, False
    processed_versions = 0
    complete = True
    for vulnerability in vulnerabilities[:100_000]:
        if deadline is not None and time.monotonic() >= deadline:
            complete = False
            break
        if not isinstance(vulnerability, dict):
            continue
        vulnerability_id = vulnerability.get("id")
        if (
            not isinstance(vulnerability_id, str)
            or not vulnerability_id
            or len(vulnerability_id) > 128
        ):
            continue
        affected_items = vulnerability.get("affected", [])
        if not isinstance(affected_items, list):
            continue
        for affected in affected_items[:1000]:
            if deadline is not None and time.monotonic() >= deadline:
                complete = False
                break
            if not isinstance(affected, dict):
                continue
            package = affected.get("package", {})
            if not isinstance(package, dict):
                continue
            ecosystem = str(package.get("ecosystem", ""))
            name = _normal(str(package.get("name", "")))
            versions = affected.get("versions", [])
            if not isinstance(versions, list):
                continue
            for version in versions[:10_000]:
                if (
                    processed_versions >= MAX_OSV_VERSION_RECORDS
                    or (deadline is not None and time.monotonic() >= deadline)
                ):
                    complete = False
                    break
                processed_versions += 1
                matches.setdefault((ecosystem.lower(), name, str(version)), []).append(
                    vulnerability_id
                )
            if not complete:
                break
        if not complete:
            break
    return matches, complete


def analyze_dependencies(
    root: Path,
    max_bytes: int = 1_000_000,
    osv_database: Path | None = None,
    *,
    deadline: float | None = None,
) -> tuple[list[dict[str, Any]], list[Node], list[Edge], list[Finding], dict[str, Any]]:
    """Inventory direct/transitive dependencies within the shared scan time budget."""
    if deadline is not None and time.monotonic() >= deadline:
        return [], [], [], [], {
            "status": "partial", "dependency_count": 0,
            "direct_count": 0, "transitive_count": 0, "ecosystems": [],
            "offline_advisory_database": osv_database is not None,
            "advisory_matches": 0, "max_dependencies": MAX_DEPENDENCIES,
            "network_access": False, "deadline_reached": True,
            "limitations": [
                "Dependency analysis was skipped because the scan time budget expired."
            ],
        }
    manifests = _python_manifest(root, max_bytes)
    entries = _lock_dependencies(root, max_bytes, manifests)
    if deadline is not None and time.monotonic() >= deadline:
        return [], [], [], [], {
            "status": "partial", "dependency_count": 0,
            "direct_count": 0, "transitive_count": 0, "ecosystems": [],
            "offline_advisory_database": osv_database is not None,
            "advisory_matches": 0, "max_dependencies": MAX_DEPENDENCIES,
            "network_access": False, "deadline_reached": True,
            "limitations": ["Dependency metadata parsing reached the scan time budget."],
        }
    # Merge direct manifest constraints into resolved lock entries instead of
    # reporting each package twice (once requested and once locked).
    manifest_items = manifests + [
        item for item in entries
        if not item.get("version")
        and item.get("source") in {
            "package.json", "Cargo.toml", "composer.json", "pom.xml"
        }
    ]
    for item in manifest_items:
        matches = [
            entry for entry in entries
            if entry is not item
            and entry["ecosystem"] == item["ecosystem"]
            and _normal(entry["name"]) == _normal(item["name"])
            and entry.get("version")
        ]
        if matches:
            for match in matches:
                match["direct"] = "true"
                match.setdefault("requested", item.get("requested", ""))
                match.setdefault("manifest_source", item.get("source", ""))
            if item in entries:
                entries.remove(item)
        elif item not in entries:
            entries.append({
                **item,
                "version": "",
                "direct": "true",
            })

    advisory_map, advisory_complete = _load_osv_exact_matches(
        osv_database, max_bytes, deadline=deadline
    )
    output: list[dict[str, Any]] = []
    nodes: list[Node] = []
    edges: list[Edge] = []
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    dependency_deadline_reached = False
    for item in entries[:MAX_DEPENDENCIES]:
        if deadline is not None and time.monotonic() >= deadline:
            dependency_deadline_reached = True
            break
        ecosystem = str(item.get("ecosystem", "unknown"))
        name = str(item.get("name", ""))
        version = str(item.get("version", ""))
        raw_requested = str(item.get("requested", ""))
        requested = _redact_source(raw_requested)
        key = (ecosystem, _normal(name), version, requested)
        if not name or key in seen:
            continue
        seen.add(key)
        direct = str(item.get("direct", "false")).lower() == "true"
        source_path = str(item.get("source", "unknown"))
        manifest_source = str(item.get("manifest_source", ""))
        raw_resolved_source = str(item.get("resolved_source", ""))
        resolved_source = _redact_source(raw_resolved_source)
        flags = _risk_flags(raw_requested, version, raw_resolved_source)
        if not version:
            flags.append("not_resolved_in_lockfile")
        advisory_ids = advisory_map.get((ecosystem.lower(), _normal(name), version), [])
        if advisory_ids:
            flags.append("known_advisory_match")
        record = {
            "ecosystem": ecosystem, "name": name, "version": version,
            "requested": requested[:512], "direct": direct,
            "source": source_path, "manifest_source": manifest_source,
            "resolved_source": resolved_source[:2048],
            "risk_flags": sorted(set(flags)),
            "advisory_ids": sorted(set(advisory_ids)),
        }
        output.append(record)
        node_id = f"dependency:{ecosystem}:{_normal(name)}:{version or 'unresolved'}"
        nodes.append(Node(
            node_id, "dependency", name, source_path,
            metadata={
                "ecosystem": ecosystem, "version": version,
                "direct": direct, "risk_flags": record["risk_flags"],
                "advisory_ids": record["advisory_ids"],
            },
        ))
        edges.append(Edge(
            f"file:{source_path}", node_id, "declares_dependency",
            Evidence(source_path, None, "Package manifest or lockfile entry."),
        ))
        for flag in record["risk_flags"]:
            severity = {
                "known_advisory_match": "high",
                "external_or_git_source": "medium",
                "wildcard_or_latest_version": "high",
                "mutable_reference": "high",
                "version_not_declared": "medium",
                "unbounded_version_constraint": "medium",
                "local_path_dependency": "low",
                "not_resolved_in_lockfile": "low",
                "non_exact_version_constraint": "medium",
            }.get(flag, "low")
            message = (
                "Dependency version matches an entry in the supplied offline OSV dataset."
                if flag == "known_advisory_match"
                else f"Dependency metadata risk indicator: {flag}."
            )
            findings.append(Finding(
                f"dependency_{flag}", severity, message,
                Evidence(source_path, None, f"{ecosystem}:{name}"),
            ))
    summary = {
        "status": (
            "partial" if not advisory_complete or dependency_deadline_reached
            else "analyzed"
        ),
        "dependency_count": len(output),
        "direct_count": sum(item["direct"] for item in output),
        "transitive_count": sum(not item["direct"] for item in output),
        "ecosystems": sorted({item["ecosystem"] for item in output}),
        "offline_advisory_database": osv_database is not None,
        "advisory_matches": sum(bool(item["advisory_ids"]) for item in output),
        "max_dependencies": MAX_DEPENDENCIES,
        "network_access": False,
        "deadline_reached": dependency_deadline_reached or not advisory_complete,
        "osv_dataset_complete": advisory_complete,
        "max_osv_version_records": MAX_OSV_VERSION_RECORDS,
        "limitations": [
            "Dependency metadata is static and lockfile-dependent.",
            "Indirect relationships may be incomplete when an ecosystem lockfile is absent.",
            "OSV matching uses exact package, ecosystem, and version entries "
            "from a supplied offline dataset.",
            "No registry resolution, package installation, or automatic network "
            "advisory lookup occurs.",
        ],
    }
    return output, nodes, edges, findings, summary
