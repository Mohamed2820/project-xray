# Security Hardening Baseline

## Implemented controls

- Source files are parsed as data; the default scan path does not import or execute target-project code.
- Filesystem traversal streams directory entries, does not follow symbolic links, and caps depth and visited entries.
- The scanner caps individual file size, file count, aggregate bytes, and elapsed scan time. A limit produces an explicitly partial report; it is never labeled as complete.
- Python source and secret scans use bounded reads and reject symbolic links/non-regular files where the host supports \`O_NOFOLLOW\`.
- Secret matches report only rule IDs and locations. Matched values and source snippets are not copied into findings.
- JSON reports are written atomically with private temporary-file permissions and reject an existing destination symlink.
- SQLite history rejects a symlink database path, uses private file permissions on POSIX, parameterized SQL, and disables trusted schema.
- Third-party analyzer entry points require an exact allowlist and remain trusted in-process code; they are not sandboxed.
- GitHub Actions use full commit-SHA pins, read-only repository permissions, no persisted checkout credentials, timeouts, Bandit, and pip-audit.
- Dependabot checks Python packages and GitHub Actions weekly.

## Default resource limits

| Limit | Default |
|---|---:|
| Individual file | 1,000,000 bytes |
| Files per scan | 20,000 |
| Aggregate file bytes | 512 MiB |
| Scan wall-clock budget | 120 seconds |
| Filesystem entries visited | 100,000 |
| Directory depth | 64 |

Applications may lower or raise scanner limits explicitly. A custom connector or third-party plugin must enforce equivalent safety boundaries. The wall-clock budget is checked between analyzer calls; it cannot forcibly terminate an in-process plugin that hangs. Only load reviewed plugins.

## GitHub repository settings still required

Workflow files cannot enforce repository-level branch protection by themselves. In GitHub
repository **Settings → Rules → Rulesets**, create an active branch ruleset targeting
\`main\` and enable:

1. Require a pull request before merging (zero required approvals is suitable for a
   single-maintainer repository; add independent reviewers when available).
2. Require status checks: \`test (3.13)\` and \`security\`.
3. Block force pushes and branch deletion.
4. Do not grant routine bypass to administrators; retain emergency bypass only if you
   intentionally accept that risk.

The connected GitHub operations used for this change can write repository files and refs,
but do not expose a ruleset/branch-protection mutation. Therefore these settings must be
applied in GitHub Settings by a repository administrator.

## Important limits

This is a hardening baseline, not a claim of zero vulnerabilities or a penetration-test
certification. Secret detection is heuristic and can miss novel formats, encoded values,
secrets split across lines, encrypted material, and secrets outside scanned paths. Static
analysis does not prove runtime safety. Keep dependencies and the host OS updated, review
security alerts, and retest after material changes.
