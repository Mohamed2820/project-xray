# First-version release acceptance

This checklist is the release gate for the first usable Project X-Ray version. It distinguishes implemented/tested behavior from intentional coverage limits. A criterion is verified only by its listed code path and automated test; a passing CI run is evidence for that commit, not a claim that the product is free of defects.

## Acceptance matrix

| Acceptance criterion | Implementation / evidence | Automated verification |
|---|---|---|
| Engine runs without known startup/runtime errors in the tested environment | CLI entry point, engine, static scan and Python runtime adapter | `tests/test_cli.py`, `tests/test_connector_engine.py`, `tests/test_runtime_cli.py`, `tests/test_runtime_integration.py` |
| Arabic HTML interface | HTML declares Arabic language and RTL direction; local read-only dashboard serves its script from the same origin | `tests/test_web.py::test_dashboard_serves_arabic_html_and_report_history` and release dashboard contract test |
| File analysis and function display | Python AST produces file/class/function/import/call nodes; dashboard details now list the functions and their parameters and line numbers | `tests/test_python_analyzer.py`, `tests/test_real_project_benchmark.py`, `tests/test_release_acceptance.py` |
| Interactive relationship map | SVG graph renders nodes/edges; nodes support pointer and keyboard activation and expose accessible labels | `tests/test_graph.py`, release dashboard contract test |
| Dependency and library analysis | Manifest/lockfile inventory, direct/transitive classification and optional offline exact-match OSV lookup | `tests/test_stage3_dependencies.py`, `tests/test_stage3_integration.py` |
| Secret detection and value redaction | Credential-pattern findings are emitted without including the detected value | `tests/test_secrets.py`, release scan acceptance test |
| Permission and risk analysis | Android manifest, selected GitHub Actions, Dockerfile and selected deployment configuration checks | `tests/test_stage3_permissions.py`, `tests/test_stage3_integration.py` |
| Change history and execution observation | SHA-256 snapshot comparison; explicit Python trace sessions; repair and test history records | `tests/test_stage3_changes.py`, `tests/test_runtime_integration.py`, `tests/test_runtime_storage.py`, `tests/test_storage.py` |
| Error recording and source correlation | Runtime exceptions, tracebacks, timeline and heuristic root-cause candidates; dashboard source links navigate to the matching scanned file | `tests/test_runtime_integration.py`, `tests/test_runtime_root_cause.py`, `tests/test_release_acceptance.py` |
| Data-flow and decision tracking | Bounded local interprocedural taint analysis and explicit Markdown ADR inventory | `tests/test_stage3_dataflow.py`, `tests/test_stage3_decisions.py`, `tests/test_stage3_integration.py` |
| Automated tests pass | Pytest test suite on the supported CI Python matrix | CI `test` matrix |
| CI and security scans pass | Ruff, Bandit, pip-audit and controlled multi-project benchmark | CI `test`, `security` and `benchmark` jobs |
| Install, run and integrate documentation | README quick start; architecture, dashboard, runtime, plugin and security documents | Documentation review plus install/CLI tests |

## Verification commands

From the repository root:

```bash
python -m pip install -e ".[dev,security]"
ruff check .
pytest
python -m benchmarks.run
bandit -r src -ll
pip-audit
```

CI runs the test suite on Python 3.11, 3.12 and 3.13. The security job runs Bandit and pip-audit, while the benchmark job runs the controlled three-project corpus.

## First-run procedure

1. Install the project and optional development/security tools using the commands above.
2. Run a non-executing static scan and save its report outside the scanned project:

   ```bash
   xray scan ./path/to/project --output ../project-report.json
   ```

3. Open the Arabic dashboard:

   ```bash
   xray web --report ../project-report.json
   ```

4. For persisted changes and runtime history, configure an external SQLite database and use repeated scans. Runtime tracing is opt-in and executes the chosen Python program:

   ```bash
   xray scan ./path/to/project --output ../report.json --database ../xray-history.sqlite3
   xray trace-python --output ../runtime-report.json --database ../xray-history.sqlite3 ./path/to/project app.py
   xray web --database ../xray-history.sqlite3 --project ./path/to/project
   ```

5. To extend the analyzer, implement the documented plugin contract and load only an explicitly reviewed entry-point name. Plugins execute in-process and are trusted code.

## Scope and non-goals of the first version

- Built-in semantic and runtime analysis is Python-focused. Other ecosystems currently contribute dependency/configuration metadata only where supported by their parsers.
- Cross-file data-flow resolution is bounded to explicit imports and local top-level Python functions. Dynamic imports, reflection, instance dispatch and complete alias/sanitizer modeling are not implemented.
- Runtime tracing is **not a sandbox**. The child runs with the caller's operating-system permissions. Use it only with trusted programs, preferably inside externally enforced disposable isolation.
- The relationship graph limits its rendered subset for readability; the report retains the full graph.
- Static permission checks inspect declarations and configuration. They do not prove effective runtime permissions.
- Secret and vulnerability checks are heuristic and dependent on supported patterns, metadata, lockfiles and optional offline OSV data.
- The controlled benchmark is synthetic and measures expected-positive coverage; it is not a production penetration test or a complete precision/recall evaluation.

A release-ready CI result means that the committed test, lint, security and benchmark jobs passed for that exact commit. It does not mean every project is fully understood or that all security risks have been eliminated.
