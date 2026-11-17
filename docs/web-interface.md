# Arabic HTML dashboard

## Start

Use an existing report:

    xray web --report ../project-report.json

Or use the external SQLite history database for the selected project:

    xray web --database ../xray-history.sqlite3 --project ./my-project

The default listener is 127.0.0.1:8765. The server rejects non-loopback IPv4 addresses. Open the URL printed by the command in a browser and stop it with Ctrl+C.

## Included sections

- Project dashboard and scan coverage.
- File explorer with metadata, hashes, related graph nodes, and findings.
- SVG project relationship graph and heuristic data-flow paths.
- Runtime error/session history and event timeline.
- Dependency inventory, redacted security findings, and change history.
- Repair/test records and explicit Markdown Architecture Decision Records (ADR).

The UI uses the scan report schema and SQLite history tables already produced by X-Ray. Missing information is shown as an empty state; the dashboard does not fabricate scan results. The file details panel shows report metadata and evidence references, not source-file contents.

## Security boundaries

- The HTTP server binds to IPv4 loopback only. It is intended for the same device, not LAN or public exposure.
- The API supports read-only GET requests. POST, PUT, and DELETE are rejected.
- SQLite is opened with mode=ro, query_only, and trusted_schema=OFF. The dashboard does not call schema initialization or write to the database.
- Report/database paths must be regular files and cannot be symbolic links at validation time. Report JSON and runtime JSON have size limits.
- Responses set Cache-Control: no-store, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, a restrictive Content Security Policy, and a permissions policy that disables camera, microphone, and geolocation.
- Dynamic text is rendered with DOM text nodes rather than HTML injection. No external scripts, fonts, analytics, or CDN resources are loaded.
- The dashboard is not an authentication system. Do not bind it to a non-loopback interface or put it behind an unauthenticated proxy.
- trace-python remains explicitly executable and is not sandboxed. The dashboard only displays telemetry already written by that command; it does not launch it.

## Current display limitations

- The SVG view limits its visible subset to 140 nodes and 260 edges for readability; full totals remain available from the report.
- Dependency, data-flow, ADR, and finding coverage is limited by the underlying analyzers and the scan coverage metadata.
- Runtime history requires an external database and an explicitly recorded Python trace.
- Data-flow tracing and root-cause correlation are heuristic, not proof of exploitability or causation.