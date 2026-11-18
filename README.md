# Project X-Ray

**Universal Project Intelligence and Observability Platform**

Project X-Ray statically inspects software projects, builds an evidence-backed component graph, and offers an explicitly opted-in Python runtime observer.

## Current implementation

Phases 1–4 provide:

- Read-only local filesystem inventory, symlink protection, and resource budgets.
- Python file, class, function, import, and call-site analysis.
- Direct and lockfile-resolved dependency inventory for Python, npm, Cargo, Go, Composer, Maven, and NuGet metadata where available.
- Dependency risk indicators and optional exact-version matching against a user-supplied offline OSV JSON dataset.
- Redacted credential detection.
- Static Android manifest, GitHub Actions, Dockerfile, and selected Kubernetes/Compose permission and deployment checks.
- Bounded Python data-flow tracing within functions and across explicitly imported local top-level functions; dynamic dispatch and relative/dynamic imports are not fully resolved.
- Explicit Markdown Architecture Decision Record (ADR) inventory.
- SHA-256 file history and impact summaries between persisted X-Ray SQLite snapshots.
- Python runtime collection for function calls/returns, selected process/network/filesystem/thread audit events, and exception stack traces.
- Event chronology reconstruction, runtime-to-static component correlation, heuristic root-cause confidence, and affected caller-component summaries.
- SQLite runtime sessions, repair-attempt records, and test-result history.
- Three-project controlled benchmark corpus covering vulnerable API handlers, Android/CI permissions, transitive dependencies, generated files, synthetic secrets, and a local runtime transport stub.
- CI on Python 3.11–3.13 with Ruff, pytest, Bandit, pip-audit, and the project benchmark.

The built-in semantic and runtime adapters currently support Python. The runtime adapter protocol is an extension point for future language-specific collectors; it does not imply those collectors are already implemented.

## Install

    python -m pip install -e ".[dev]"

Security checks:

    python -m pip install -e ".[dev,security]"
    bandit -r src -ll
    pip-audit

## Static scan

Basic scan:

    xray scan ./path/to/project --output ../project-report.json

Persist history and enable snapshot-based change analysis:

    xray scan ./path/to/project --output ../report.json --database ../xray-history.sqlite3

Run a later scan with the same external database to compare additions, modifications, and deletions:

    xray scan ./path/to/project --output ../report-next.json --database ../xray-history.sqlite3

Optionally compare exact package/version pairs with a locally supplied OSV JSON database:

    xray scan ./path/to/project --output ../report.json --osv-db ../osv-offline.json

The supported offline dataset shape is an OSV JSON object with a top-level vulns list, package ecosystem/name, and affected versions entries. This mode performs exact-version matching only; it does not resolve ranges or make network calls.

## Explicit Python runtime observation

**Important:** trace-python executes the selected script. It is not a sandbox. The target inherits the current user's operating-system permissions and environment and can access files or the network that the user can access. Use it only with code you trust.

Example with a report and persistent history stored outside the project:

    xray trace-python --output ../runtime-report.json --database ../xray-history.sqlite3 --max-events 10000 --max-seconds 120 ./my-project app.py -- --verbose

The options must appear before the project and script paths. Arguments after the separator -- are passed to the target program.

The collector records Python function calls/returns and selected audit event categories. It records no function arguments, local-variable values, return values, environment variables, command arguments, stdout/stderr, file contents, or network payloads. Exception messages are redacted with the project's credential patterns; stack traces contain project-relative paths, line numbers, and function names, not source snippets.

Default runtime limits: 10,000 events and 120 seconds. Maximums: 100,000 events and 600 seconds. The parent discards child stdout/stderr and terminates remaining members of the runtime process group after normal exit and on timeout on POSIX systems. Windows terminates the observed process; complete descendant cleanup requires a Windows Job Object backend.

List previous sessions:

    xray runtime-history --database ../xray-history.sqlite3

## Record repair attempts and test results

This command records a repair outcome and a test result already obtained elsewhere. It does not edit files, execute a repair, or run the supplied test command:

    xray record-repair --database ../xray-history.sqlite3 --project ./my-project --summary "Fixed failing parser edge case" --outcome applied --changed-file src/parser.py --test-command "pytest -q" --test-exit-code 0 --test-summary "68 passed"

Review history:

    xray repair-history --database ../xray-history.sqlite3
    xray test-history --database ../xray-history.sqlite3

The recorded command, summary, and file paths are redacted before persistence.

## Arabic HTML dashboard

Start a local, read-only dashboard from an existing report or an external SQLite history database:

    xray web --database ../xray-history.sqlite3 --project ./my-project

Or open one saved JSON report:

    xray web --report ../project-report.json

The dashboard listens on IPv4 loopback only (default 127.0.0.1:8765). It does not expose a public network listener, execute project code, modify files, or write to the database. Open the printed local address in a browser. Stop the server with Ctrl+C. See docs/web-interface.md for the data sources and security boundaries.

## Analysis boundaries

- The default scan path does not execute project code, install dependencies, contact package registries, or send source files to an AI service.
- Dependency transitive coverage depends on the ecosystem's available lockfile.
- Dependency risk flags are metadata heuristics. A known advisory is reported only when an exact package/ecosystem/version matches the supplied offline OSV dataset.
- Android declarations do not prove user grants or actual runtime use.
- Data-flow tracing is heuristic and intra-function; it does not prove exploitability or model all sanitizers, aliases, dynamic behavior, or cross-file flows.
- Change analysis requires persisted snapshots and compares file hashes; it does not infer Git authors or commits.
- ADR analysis only reports explicit Markdown records in recognized locations.
- Runtime instrumentation currently observes Python only. Selected audit events are not an exhaustive OS monitor; native activity, child-process internals, and other language runtimes can be missed.
- Root-cause confidence is heuristic correlation, not proof. Low-confidence matches must be reviewed.
- Runtime telemetry may be incomplete if event/time limits are reached or a process terminates abruptly. It is not tamper-proof against the executed target.
- A clean report does not prove absence of secrets, vulnerabilities, or runtime defects.

Default static limits: 1 MB per file, 20,000 files, 512 MiB aggregate bytes, 120 seconds per scan, 100,000 filesystem entries, and 64 directory levels. Reports identify partial scans and unsupported analysis.

Third-party analyzer plugins require an exact trust allowlist and execute in-process. They are not sandboxed:

    xray scan ./source --load-plugins --trusted-plugin reviewed-plugin-name

See docs/runtime-monitoring.md, docs/security-hardening.md, docs/architecture.md, and docs/plugins.md.


## Phase 6: controlled real-project benchmark

Run the adversarial multi-project corpus and its explicit expected-result checks:

    python -m benchmarks.run

The corpus covers a multi-module Python API, Android/CI permissions, direct and indirect
dependencies, synthetic credentials, unsafe data flows, generated files, parse failures,
and a safe stubbed runtime probe. Results report expected-positive coverage and known gaps;
they do not claim precision or production security certification. See
[benchmarks/README.md](benchmarks/README.md).


## Security audit and hardening

A six-stage code-level security review and its regression tests are documented in
[docs/security-audit.md](docs/security-audit.md). The review hardened source-path
validation, database placement, credential redaction, runtime child-process handling,
dashboard content security policy, and dependency-advisory resource limits.

The review's CI is evidence for the tested cases, not a claim that every vulnerability
has been eliminated. Runtime tracing is **not a sandbox**, third-party plugins execute
in-process as trusted code, Windows descendant cleanup remains limited, and production
deployment security still requires environment-specific penetration testing.

## License

MIT. See LICENSE.
