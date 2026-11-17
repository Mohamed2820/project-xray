# Project X-Ray

**Universal Project Intelligence and Observability Platform**

Project X-Ray is a safety-first platform for inspecting software projects, building an evidence-backed project graph, and producing machine-readable scan snapshots.

## Current implementation

Phase 1 and the central-engine foundation are implemented:

- Read-only local filesystem connector with symlink and generated-directory exclusions.
- Central X-Ray orchestration engine.
- Plugin registry with a built-in Python AST analyzer and an explicit allowlist for third-party entry points.
- Directed Graph Engine with neighborhood, upstream-impact, downstream-impact, and integrity queries.
- SQLite Data Engine for opt-in local scan history.
- JSON reports with schema version, scan identity, timestamps, evidence, and coverage metadata.
- CLI for scanning and viewing history.
- CI on Python 3.11, 3.12, and 3.13, plus Bandit and pip-audit security checks.

The bundled semantic analyzer currently supports Python. Other recognized source files are inventoried and marked as inventory-only until an analyzer plugin is installed. Runtime tracing, deep dependency vulnerability intelligence, permission analysis, data lineage, decision records, and the Arabic dashboard remain later milestones.

## Requirements and installation

- Python 3.11+
- Development install:

\`\`\`bash
python -m pip install -e ".[dev]"
\`\`\`

- Security tooling:

\`\`\`bash
python -m pip install -e ".[dev,security]"
bandit -r src -ll
pip-audit
\`\`\`

## CLI

Write a JSON report outside the scanned project:

\`\`\`bash
xray scan ./path/to/project --output ../project-report.json
\`\`\`

Save an additional SQLite history snapshot outside the scanned project:

\`\`\`bash
xray scan ./path/to/project \\
  --output ../project-report.json \\
  --database ../xray-history.sqlite3
xray history --database ../xray-history.sqlite3 --limit 20
\`\`\`

Default resource limits are 1 MB per file, 20,000 files, 512 MiB total file bytes,
120 seconds per scan, 100,000 filesystem entries, and 64 directory levels.
Adjust scanner limits only for trusted projects and available resources. Reports
state explicitly when a limit caused a partial scan.

Third-party plugin loading is opt-in and requires an exact allowlist. Plugins execute
inside the X-Ray process and are not sandboxed; review and pin them before trusting:

\`\`\`bash
xray scan ./source --load-plugins --trusted-plugin reviewed-plugin-name
\`\`\`

## Safety boundaries

- Scanning source files does not import or execute the target project's code.
- Local traversal does not follow symbolic links and excludes common generated/vendor directories.
- Reads are bounded; secret values are never included in findings.
- No network calls or external AI processing are performed by the core.
- JSON and SQLite output must be placed outside the project being scanned.
- A clean scan is not proof that a project is secure or completely understood.

See [docs/security-hardening.md](docs/security-hardening.md), [docs/architecture.md](docs/architecture.md), and [docs/plugins.md](docs/plugins.md).

## License

MIT. See [LICENSE](LICENSE).
