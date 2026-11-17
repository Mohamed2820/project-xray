# Project X-Ray

**Universal Project Intelligence and Observability Platform**

Project X-Ray statically inspects software projects, builds an evidence-backed project graph, and produces machine-readable scan snapshots.

## Current implementation

Phases 1–3 provide:

- Read-only local filesystem inventory, symlink protection, and resource budgets.
- Python file, class, function, import, and call-site analysis.
- Direct and lockfile-resolved dependency inventory for Python, npm, Cargo, Go, Composer, Maven, and NuGet metadata where available.
- Dependency risk indicators and optional exact-version matching against a user-supplied offline OSV JSON dataset.
- Redacted credential detection.
- Static Android manifest, GitHub Actions, Dockerfile, and selected Kubernetes/Compose permission and deployment checks.
- Heuristic intra-function Python data-flow tracing from recognized input sources to sensitive sinks.
- Explicit Markdown Architecture Decision Record (ADR) inventory.
- SHA-256 file history and impact summaries between persisted X-Ray SQLite snapshots.
- Directed Graph Engine, SQLite report history, and JSON output.
- CI on Python 3.11–3.13 with Ruff, pytest, Bandit, and pip-audit.

The built-in semantic source analyzer is Python-focused. Other language files are inventoried and may contribute dependency/config metadata but are not semantically parsed unless a compatible analyzer plugin is registered.

## Install

    python -m pip install -e ".[dev]"

Security checks:

    python -m pip install -e ".[dev,security]"
    bandit -r src -ll
    pip-audit

## Scan

Basic scan:

    xray scan ./path/to/project --output ../project-report.json

Persist history and enable snapshot-based change analysis:

    xray scan ./path/to/project --output ../report.json --database ../xray-history.sqlite3

Run a later scan with the same external database to compare additions, modifications, and deletions:

    xray scan ./path/to/project --output ../report-next.json --database ../xray-history.sqlite3

Optionally compare exact package/version pairs with a locally supplied OSV JSON database:

    xray scan ./path/to/project --output ../report.json --osv-db ../osv-offline.json

The supported offline dataset shape is an OSV JSON object with a top-level vulns list, package ecosystem/name, and affected versions entries. This mode performs exact-version matching only; it does not resolve ranges or make network calls.

Default limits: 1 MB per file, 20,000 files, 512 MiB aggregate bytes, 120 seconds per scan, 100,000 filesystem entries, and 64 directory levels. Reports identify partial scans and unsupported analysis.

Third-party plugins require an exact trust allowlist and execute in-process. They are not sandboxed:

    xray scan ./source --load-plugins --trusted-plugin reviewed-plugin-name

## Analysis boundaries

- The default path does not execute project code, install dependencies, contact package registries, or send source files to an AI service.
- Dependency transitive coverage depends on the ecosystem's available lockfile.
- Dependency risk flags are metadata heuristics. A known advisory is reported only when an exact package/ecosystem/version matches the supplied offline OSV dataset.
- Android declarations do not prove user grants or actual runtime use.
- Data-flow tracing is heuristic and intra-function; it does not prove exploitability or model all sanitizers, aliases, dynamic behavior, or cross-file flows.
- Change analysis requires persisted snapshots and compares file hashes; it does not infer Git authors or commits.
- ADR analysis only reports explicit Markdown records in recognized locations.
- Secret matching is heuristic. A clean report does not prove the absence of secrets or vulnerabilities.

See docs/security-hardening.md, docs/architecture.md, and docs/plugins.md.

## License

MIT. See LICENSE.
