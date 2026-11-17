# Architecture

## Layer responsibilities

| Layer | Responsibility | Current boundary |
|---|---|---|
| X-Ray Core | Orchestrates one scan and exposes the graph | Synchronous local execution |
| Project Scanner | Inventory, bounded dispatch, security pattern checks | Read-only files up to configured size |
| Connectors | Expose files through a stable contract | Local filesystem connector |
| Language Analyzers | Convert source into typed graph elements | Python AST built in; static dependency/config analyzers |
| Dependency Intelligence | Direct/transitive inventory and advisory risk signals | Manifest/lockfile parsing plus optional offline exact-match OSV dataset |
| Permission Analysis | Inspect declared platform and workflow/deployment privileges | Android Manifest, GitHub Actions, Dockerfile, and selected YAML checks |
| Data Lineage | Candidate taint paths from sources to sensitive sinks | Intra-function Python AST heuristic |
| Change Intelligence | Compare additions/modifications/deletions and structural impact | SHA-256 comparison between persisted snapshots |
| Decision Intelligence | Inventory explicit ADRs and completeness | Recognized Markdown ADR paths |
| Plugin Registry | Match extensions to analyzers | Manual registration and explicit entry points |
| Graph Engine | Index directed relationships and calculate impact | In-memory graph |
| Data Engine | Save/retrieve scan snapshots | SQLite, schema version 1 |
| Report Engine | Stable JSON representation | Report schema 1.2 |

## Scan flow

```text
Input path or ProjectConnector
          |
          v
    XRayEngine.scan()
          |
          v
     ProjectScanner
          |
          +----> Connector.iter_files()
          |
          +----> PluginRegistry.analyzers_for(extension)
          |              |
          |              v
          |        AnalyzerPlugin
          |
          +----> Secret pattern scanner (redacted output)
          |
          v
     ScanReport (nodes, edges, findings, coverage)
          |
          +----> ProjectGraph (indexes and impact queries)
          |
          +----> optional SQLiteDataEngine.save_report()
          |
          +----> JSON report
```

## Graph semantics

Edges are directed from an owner/source to a referenced/target node. Examples:

- `file --contains--> function`
- `file --imports--> import symbol`
- `function --calls--> call site`

Upstream impact follows incoming edges to owners/dependents. Downstream traversal follows outgoing edges to referenced components. Each edge carries an evidence path and optional line number.

## Data lifecycle

Each scan has a unique `scan_id`, UTC creation time, root path, report schema version, counts, and serialized report. SQLite history is opt-in and local. Schema upgrades use SQLite's `user_version`; opening a database with a newer unsupported schema fails safely rather than downgrading it.

## Extension points

A connector implements `ProjectConnector`; an analyzer implements `AnalyzerPlugin`. New languages and source types should be added through these contracts rather than by coupling language logic to the engine.

## Trust and safety

Static analyzers must parse data, not execute scanned source. Only explicitly loaded, reviewed third-party plugins are imported. Core scanning does not perform network access. Persisted reports must not contain secret values; all findings should retain location and rule evidence only.
