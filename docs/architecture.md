# Architecture

## Layer responsibilities

| Layer | Responsibility | Current boundary |
|---|---|---|
| X-Ray Core | Orchestrates scans and exposes the graph | Synchronous local execution |
| Project Scanner | Inventory, bounded dispatch, static security checks | Read-only files up to configured size |
| Connectors | Expose files through a stable contract | Local filesystem connector |
| Language Analyzers | Convert source into typed graph elements | Python AST built in; static dependency/config analyzers |
| Dependency Intelligence | Direct/transitive inventory and advisory risk signals | Manifest/lockfile parsing plus optional offline exact-match OSV dataset |
| Permission Analysis | Inspect declared platform and workflow/deployment privileges | Android Manifest, GitHub Actions, Dockerfile, and selected YAML checks |
| Data Lineage | Candidate taint paths from sources to sensitive sinks | Bounded Python AST heuristic; follows explicitly imported local top-level functions across files |
| Change Intelligence | Compare additions/modifications/deletions and structural impact | SHA-256 comparison between persisted snapshots |
| Decision Intelligence | Inventory explicit ADRs and completeness | Recognized Markdown ADR paths |
| Runtime Adapter | Capture language-specific calls, events, and errors | Python adapter; protocol supports future adapters |
| Runtime Collector | Record bounded call and audit events | Python profile hooks and selected audit events |
| Timeline Engine | Reconstruct event chronology and function spans | Monotonic timestamps and call/return pairing |
| Root-Cause Correlator | Match runtime tracebacks to static components | Heuristic path/function correlation with confidence |
| Repair/Test History | Record repair outcomes and externally obtained test results | SQLite; does not edit code or execute recorded commands |
| Plugin Registry | Match extensions to analyzers | Manual registration and explicit entry points |
| Graph Engine | Index directed relationships and calculate impact | In-memory graph |
| Data Engine | Save scans, runtime sessions, repairs and test results | SQLite schema version 2 |
| Report Engine | Stable JSON representation | Report schema 1.2 |

## Static scan flow

1. XRayEngine accepts a project path or connector.
2. ProjectScanner inventories bounded regular files.
3. Built-in and explicitly registered analyzers generate nodes, edges, and findings.
4. Dependency, permission, data-flow, decision, and secret analysis enrich the report.
5. ProjectGraph calculates graph relationships and impact.
6. JSON output and optional SQLite history persist the report.

## Runtime observation flow

1. The user explicitly calls trace-python.
2. X-Ray performs a bounded static scan without executing project files.
3. A Python child process is launched without a shell.
4. Python profile hooks observe project function calls and returns.
5. Selected audit events capture categories for process, network, filesystem, and thread activity; arguments are discarded.
6. Unhandled exceptions are captured with redacted messages and project-relative stack frames.
7. Events are sorted using a shared monotonic clock origin; observed call/return spans are reconstructed.
8. Runtime caller edges and static function metadata are correlated to provide a heuristic root-cause candidate.
9. The combined report and optional SQLite session history are written.

The child process is an execution boundary for crash/timeout handling, not a security sandbox. It inherits the caller's OS permissions and environment.

## Graph semantics

Edges are directed from an owner/source to a referenced/target node. Examples:

- file --contains--> function
- file --imports--> import symbol
- function --calls--> call site
- runtime caller --runtime_calls--> runtime callee
- runtime function --matches_static_component--> static function

Upstream impact follows incoming edges to callers/owners. Every edge carries an evidence path and optional line number. Runtime edges are only created for calls observed during that session.

## Data lifecycle

Each static scan has a unique scan_id, UTC creation time, root path, report schema version, counts, and serialized report. Each runtime session has a session_id, timestamps, exit status, bounded event list, and reconstructed timeline. SQLite history is opt-in and local. The database migrates from schema version 1 to version 2 by adding runtime-session/event, repair-attempt, and test-run tables without removing scan rows.

Repair/test records contain a caller-provided outcome and an already-observed test exit code. They are records, not claims that X-Ray performed the repair or executed the test.

## Extension points

A connector implements ProjectConnector; a static analyzer implements AnalyzerPlugin; a language observer implements RuntimeAdapter. New language observers must document coverage, execution model, event limits, and whether their target process is isolated.

## Trust and safety

Static analyzers parse data and do not execute scanned source. Runtime collection executes only through the explicit trace-python command. Runtime reports omit function arguments, local values, return values, environment values, command arguments, stdout/stderr, source snippets, and network payloads. Selected audit events are recorded by category only. Runtime code has no OS sandbox and can access everything available to the invoking user. Third-party plugins are trusted in-process code and are not sandboxed.
