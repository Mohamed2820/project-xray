# Phase 6: Project Benchmark Corpus

This phase adds three controlled, realistic project fixtures:

| Project | Scenarios |
|---|---|
| `commerce_api` | Multi-module Python app, SQL/command/dynamic-code/outbound-HTTP taint, fake credential, Poetry direct/transitive dependencies, Git dependency with fake credentials, syntax error and generated client |
| `mobile_admin` | Android sensitive permissions and a deliberately over-privileged GitHub Actions workflow |
| `async_worker` | npm direct/transitive lock entries, generated client, dynamic Python operation, simulated external transport and opt-in runtime tracing |

## Run

```sh
python -m pip install -e ".[dev,security]"
python benchmarks/run.py
pytest -q
```

The corpus is stored declaratively in `corpus.py` and materialized into a temporary
workspace for each run. It uses only local files and `osv-fixtures.json`; it installs no
packages and accesses no registries or external services. Static scanning does not execute
the fixtures. The separate runtime probe executes only reviewed sample code, calling a local
stub that returns a fixed response and never opens a socket.

## Measurement rules

- Expected findings match by rule ID **and** evidence path.
- Dependency counts, inventory paths, parser-error status, AST calls and imports are checked
  independently.
- The percentage measures expected-positive coverage, **not precision**. The corpus does not
  claim complete labels for every possible finding.
- Cross-file taint is reported as a known, measured gap: the current engine is intentionally
  intra-function.
- Synthetic package names, fake credentials, a reserved `.invalid` hostname and a test-only
  advisory ID are used. No real credential or vulnerability is asserted.

This controlled regression benchmark is not an independent security certification or a
production penetration test.
