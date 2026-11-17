# Project X-Ray

**Universal Project Intelligence and Observability Platform**

Project X-Ray is a safety-first toolkit for inspecting software projects, building an evidence-backed project graph, and producing machine-readable reports.

## Phase 1 baseline

This repository establishes the development foundation and a deliberately small, testable first slice:

- Non-executing filesystem scan (symlinks are not followed).
- Python source structure extraction using the standard-library AST parser.
- Import, containment, and call relationships with file/line evidence.
- Secret-pattern detection that reports locations and rule names only; secret values are never returned.
- JSON report output and a CLI.
- Pytest, Ruff, and GitHub Actions CI.

Other languages are inventoried by file extension but are not yet semantically analyzed. Runtime tracing, dependency vulnerability intelligence, permissions, data lineage, decision records, and the Arabic dashboard are planned modules, not claimed as implemented.

## Safety model

- Static scanning never imports or executes project code.
- No network calls or external AI processing are performed.
- Symlinks are skipped; common generated/vendor directories are excluded.
- Files above the configured size limit are skipped.
- Secret matches are redacted at source: reports contain no matched values.
- X-Ray does not modify scanned projects.

## Requirements

- Python 3.11+
- Install development dependencies: `python -m pip install -e ".[dev]"`

## Run

```bash
xray scan . --output xray-report.json
pytest
ruff check .
```

The report schema is versioned. Findings are evidence-backed and distinguish supported analysis from unsupported file types. A clean report does not prove the absence of vulnerabilities or undiscovered behavior.

## Architecture

```
src/xray/
  cli.py                 CLI entry point
  core/models.py         Report and graph data structures
  scanner.py             Safe filesystem inventory
  analyzers/python.py    Python AST analyzer
  analyzers/secrets.py   Redacted secret-pattern scanner
  graph.py               Relationship aggregation
  report.py              JSON serialization
tests/                   Unit and integration tests
.github/workflows/ci.yml CI pipeline
```

## Development

Run `pytest` and `ruff check .` before submitting changes. Keep analyzers deterministic, bounded, non-executing, and explicit about unsupported coverage.

## License

MIT. See [LICENSE](LICENSE).
