# Runtime Monitoring and Error Tracking

## 1. Static scans remain non-executing

The xray scan command remains a static-only operation. It inventories and parses project files but does not execute them.

## 2. Explicitly execute a Python entry point

trace-python launches the selected script in a separate Python child process. Supply options before the project and script paths:

    xray trace-python --output ../runtime-report.json --database ../xray-history.sqlite3 --max-events 10000 --max-seconds 120 ./project app.py -- --verbose

Arguments after the separator -- are forwarded to the target. The output and optional database must be outside the scanned project.

**This is not a sandbox.** The child has the current user's OS permissions and inherits its environment. The target can access permitted files and the network. Use it only with trusted code.

## 3. Runtime data collected

The current Python adapter uses sys.setprofile, threading.setprofile, and selected sys.addaudithook event categories.

- Python function calls and returns in the project: function name, project-relative path, line, caller component, thread/process IDs, monotonic time, and observed duration.
- Selected audit events: process creation/exec, socket connect/bind/address lookup, selected filesystem mutations, and thread start. Audit arguments are discarded.
- Unhandled exceptions: exception type, redacted message, and project-relative traceback frames with path/line/function.
- Parent-process lifecycle: observed child PID, start/exit, exit code, and timeout status.

The report does not store arguments, local values, return values, environment variables, command arguments, stdout/stderr, file contents, source lines, or network payloads.

## 4. Timeline and root-cause analysis

Events share a monotonic clock origin and are sorted into a deterministic sequence. Function-call and function-return pairs are reconstructed into observed spans. Abrupt termination or exceptions may leave incomplete spans.

The root-cause correlator selects the deepest project traceback frame and tries to match it to a statically parsed Python function by project path and function name. The confidence score is heuristic:

- high: function/path match found in the static graph.
- medium: file-level or partial component evidence.
- low: weak or incomplete correlation.

Affected components are derived from observed runtime caller edges and the static component graph. A candidate is not proof of causation; inspect the original code and full context.

## 5. Runtime limits and persistence

Default: 10,000 events and 120 seconds. Maximum: 100,000 events and 600 seconds. The collector marks the telemetry incomplete if a limit is reached. On POSIX the child starts a new process group, which is terminated on timeout. Windows descendant termination is platform-dependent.

With --database, X-Ray stores the runtime session, events, and combined report in SQLite schema version 2. Existing schema-version-1 scan history is retained during migration.

## 6. Repair and test history

To record a repair that was performed elsewhere and the result of a test that was already run:

    xray record-repair --database ../xray-history.sqlite3 --project ./project --summary "Fixed parser regression" --outcome applied --changed-file src/parser.py --test-command "pytest -q" --test-exit-code 0 --test-summary "68 passed"

Outcomes: attempted, applied, reverted, or failed.

The command only records supplied evidence. It does not edit files, invoke a repair, or run a test command. History can be reviewed with:

    xray runtime-history --database ../xray-history.sqlite3
    xray repair-history --database ../xray-history.sqlite3
    xray test-history --database ../xray-history.sqlite3

Credential-like content is redacted before records are persisted.

## 7. Extending language support

New runtime observers implement RuntimeAdapter and declare their language and file extensions. An adapter must define its own event model, resource limits, execution isolation, redaction policy, timeline semantics, and coverage limitations. Python is the only built-in runtime adapter at this stage.


## Runtime child environment filtering

Before starting the explicitly requested Python child, X-Ray removes environment
variables whose names look like credentials (tokens, passwords, secrets, API/access
keys, credentials, authorization values, cookies, or private keys). It also removes
Python startup/path injection variables and native loader injection hooks. A loader
search path is rebuilt from the configured Python library directory rather than
inherited from the caller. User-site imports and bytecode writes are disabled for the child.

This is a defense-in-depth measure, not an operating-system sandbox. The child still
runs as the same OS user, can read files available to that user, and can access the
network. Do not run untrusted code on a machine containing valuable credentials; use a
separate OS account or an externally enforced container/VM with network and filesystem
restrictions for that threat model.
