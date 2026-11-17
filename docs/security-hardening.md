# Security Hardening Baseline

## Implemented controls

- The default source scan parses data; it does not import or execute target-project code.
- Filesystem traversal streams directory entries, does not follow symbolic links, and caps depth and visited entries.
- The scanner caps individual file size, file count, aggregate bytes, and elapsed scan time. A limit produces an explicitly partial report; it is never labeled as complete.
- Python source and secret scans use bounded in-root reads and reject symbolic links/non-regular files where the host supports directory-descriptor and no-follow operations.
- Secret matches report only rule IDs and locations. Matched values and source snippets are not copied into findings.
- JSON reports are written atomically with private temporary-file permissions and reject an existing destination symlink.
- SQLite history rejects a symlink database path, uses private file permissions on POSIX, parameterized SQL, and disables trusted schema.
- Runtime telemetry is capped by event count and duration; it omits call arguments, locals, return values, command arguments, environment values, stdout/stderr, source snippets, and network payloads.
- Runtime stack traces contain project-relative paths, line numbers, and function names. Exception text and stored repair/test text are passed through credential-pattern redaction.
- The runtime Python child is launched without a shell. On POSIX, it runs in a new process group and that group is terminated on timeout.
- Third-party analyzer entry points require an exact allowlist and remain trusted in-process code; they are not sandboxed.
- GitHub Actions use full commit-SHA pins, read-only repository permissions, no persisted checkout credentials, timeouts, Bandit, and pip-audit.
- Dependabot checks Python packages and GitHub Actions weekly.

## Explicit runtime execution warning

trace-python executes the selected project script. It is not a sandbox. The child process inherits the current user's filesystem permissions and environment, and the program can access the network and any resource available to that user. Run it only on code you trust. The event collector reduces what X-Ray writes into its report; it does not prevent the target program itself from reading or exfiltrating secrets.

The collector records Python call/return events and selected audit categories for process, network, filesystem, and thread activity. It is not an exhaustive operating-system monitor. Native extensions, internal activity of child processes, and other language runtimes can be missed. On Windows, timeout termination of descendant processes is platform-dependent.

## Default resource limits

| Limit | Default |
|---|---:|
| Individual static file | 1,000,000 bytes |
| Static files per scan | 20,000 |
| Aggregate static file bytes | 512 MiB |
| Static scan wall-clock budget | 120 seconds |
| Filesystem entries visited | 100,000 |
| Directory depth | 64 |
| Runtime events per session | 10,000 |
| Runtime collection duration | 120 seconds |
| Python runtime source size | 5 MiB |

Runtime collection may be configured up to 100,000 events and 600 seconds. When an event/time budget is reached, telemetry is marked incomplete rather than silently claimed complete. A child process may terminate abruptly before it can flush its in-memory events.

A custom connector, analyzer, or runtime adapter must enforce equivalent safety boundaries and document its blind spots.

## GitHub repository settings still required

Workflow files cannot enforce repository-level branch protection by themselves. In GitHub
repository Settings -> Rules -> Rulesets, create an active branch ruleset targeting main
and enable:

1. Require a pull request before merging (zero required approvals is suitable for a
   single-maintainer repository; add independent reviewers when available).
2. Require status checks for the active test matrix and security job.
3. Block force pushes and branch deletion.
4. Do not grant routine bypass to administrators; retain emergency bypass only if you
   intentionally accept that risk.

These are repository settings and must be applied in GitHub Settings by a repository administrator.

## Important limits

This is a hardening baseline, not a claim of zero vulnerabilities or a penetration-test
certification. Secret detection and runtime exception redaction are heuristic and can miss
novel, encoded, split, encrypted, or otherwise unrecognized credentials. Static analysis,
runtime profiling, and heuristic root-cause correlation do not prove the absence of
defects. Runtime events are not tamper-proof against the executed target. Keep dependencies
and the host OS updated, review security alerts, and retest after material changes.
