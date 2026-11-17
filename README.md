# Project X-Ray

**Universal Project Intelligence and Observability Platform**

Project X-Ray is a safety-first platform for inspecting software projects, building an evidence-backed project graph, and producing machine-readable scan snapshots.

## Current implementation

Phase 1 and the central-engine foundation are implemented:

- Read-only local filesystem connector with symlink and generated-directory exclusions.
- Central X-Ray orchestration engine.
- Plugin registry with the built-in Python AST analyzer and an explicit entry-point extension mechanism.
- Directed Graph Engine with neighborhood, upstream-impact, downstream-impact, and integrity queries.
- SQLite Data Engine for opt-in local scan history.
- JSON reports with schema version, scan identity, timestamps, evidence, and coverage metadata.
- CLI for scanning and viewing history.
- Pytest, Ruff, and GitHub Actions CI on Python 3.11, 3.12, and 3.13.

The bundled semantic analyzer currently supports Python. Other recognized source files are inventoried and marked as inventory-only until an analyzer plugin is installed. Runtime tracing, deep dependency vulnerability intelligence, permission analysis, data lineage, decision records, and the Arabic dashboard remain later milestones.

## Requirements and installation

- Python 3.11+
- Development install:

```bash
python -m pip install -e ".[dev]"
```

## CLI

Write a JSON report outside the scanned project:

```bash
xray scan ./path/to/project --output ../project-report.json
```

Save an additional SQLite history snapshot outside the scanned project:

```bash
xray scan ./path/to/project \
  --output ../project-report.json \
  --database ../xray-history.sqlite3
xray history --database ../xray-history.sqlite3 --limit 20
```

Loading third-party analyzer entry points is opt-in because it imports installed plugin code into the X-Ray process:

```bash
xray scan ./path/to/project --output ../report.json --load-plugins
```

## Python API

```python
from xray.core.engine import XRayEngine
from xray.storage.sqlite import SQLiteDataEngine

store = SQLiteDataEngine("../xray-history.sqlite3")
engine = XRayEngine(data_engine=store)
report = engine.scan("../my-project", persist=True)

graph = engine.last_graph
affected_owners = graph.impact("function:src/app.py:10:run", direction="upstream")
```

Persistence is opt-in. X-Ray refuses to create its SQLite database or JSON report inside the scanned project.

## Architecture

```
src/xray/
  core/
    engine.py             Central orchestration
    models.py             Shared report, node, edge, and evidence models
  connectors/
    base.py               ProjectConnector protocol and FileEntry
    filesystem.py         Safe local filesystem implementation
  plugins.py              Analyzer contract, registry, entry-point discovery
  analyzers/
    python.py              Python AST analyzer
    secrets.py             Redacted secret-pattern scanner
  scanner.py               Indexing and analyzer orchestration
  graph.py                 Directed graph and impact queries
  storage/sqlite.py        Versioned SQLite report history
  report.py                JSON serialization
  cli.py                   Command line interface
tests/                    Unit and integration tests
docs/                     Architecture and plugin contracts
```

Data flow:

1. A connector exposes bounded file entries.
2. The Project Scanner inventories files and dispatches matching analyzer plugins.
3. Analyzers return typed nodes, edges, and evidence; the secret scanner emits redacted findings.
4. The Graph Engine indexes relationships and validates edge endpoints.
5. The X-Ray Core returns a report and can optionally persist a snapshot through the Data Engine.

## Safety boundaries

- Scanning source files does not import or execute the target project's code.
- Local traversal does not follow symbolic links and excludes common generated/vendor directories.
- Files larger than the configured limit are not parsed.
- Secret findings never include matched secret values.
- No network calls or external AI processing are performed by the core.
- Third-party entry-point plugins are not loaded unless explicitly requested. A loaded plugin is trusted code and executes in the X-Ray process; it must be reviewed before use.
- JSON and SQLite output must be placed outside the project being scanned.
- Coverage states identify unsupported language semantics and uncollected runtime behavior. A clean scan is not proof that a project is secure or completely understood.

## Development checks

```bash
ruff check .
pytest
```

See [docs/architecture.md](docs/architecture.md) and [docs/plugins.md](docs/plugins.md).

## License

MIT. See [LICENSE](LICENSE).
