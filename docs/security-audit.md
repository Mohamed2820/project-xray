# Project X-Ray — six-stage security review

**Review type:** repository source review plus adversarial regression tests  
**Reviewed base:** main at `e03d204d684fdbc1d43cf0c84f9773749f63d3ad`  
**Remediation branch:** `security-audit-hardening`  
**Scope:** implementation stages 1–6, CI, local dashboard, storage, runtime observer, and controlled project benchmark.

## Stage-by-stage results

| Stage | Areas reviewed | Confirmed remediations |
|---|---|---|
| 1 — discovery and file intake | Filesystem traversal, symlinks, connector trust, file metadata | Validate connector-supplied paths and file identity before including their paths or metadata in the report; reject POSIX/Windows traversal, drive-qualified paths and symlinks; report rejected entries as incomplete coverage |
| 2 — core engine and persistence | Scan side effects, project boundaries, SQLite history | Reject a configured history database located inside the scanned project even when persistence is disabled, because reading history can initialize or migrate the database |
| 3 — static analyzers and graph | Secret patterns, ADR data, dependency/OSV matching, taint propagation | Use one credential redactor in ADR output; recognize `API_TOKEN`; add bounded local interprocedural taint propagation; cap OSV version records and stop matching at the shared scan deadline; mark incomplete OSV analysis as partial |
| 4 — runtime observation | Child environment, loader injection, output, process lifetime, report files | Filter credential and Python startup variables from the child environment; rebuild the native loader path from the configured Python library directory; discard target stdout/stderr; terminate surviving POSIX process-group descendants; load child reports through a checked no-follow file descriptor |
| 5 — dashboard | Script policy, request handling, history data, concurrency | Move JavaScript to a same-origin asset; set `script-src 'self'`; bound worker concurrency, queue size, socket read time, history item counts, and returned text/JSON fields; retain read-only SQLite and loopback/Host validation |
| 6 — project benchmark | Multi-file data flow, secrets, indirect dependencies, generated files, parse errors, permissions, runtime behavior | Keep the three-project controlled corpus in CI; assert expected findings and inventory; exercise cross-file taint and runtime observation through a local stub without external network access |

## Verified CI evidence

For the latest reviewed commit, GitHub Actions completed successfully:

- Python 3.11: **113 passed**
- Python 3.12: **113 passed**
- Python 3.13: **113 passed**
- Controlled multi-project benchmark: passed
- Bandit: no issues identified
- pip-audit: no known vulnerabilities found

These results establish that the repository's defined checks passed on the tested commit. Bandit and pip-audit have their own scope and do not replace adversarial runtime testing or a production penetration test.

## Explicit residual risks and unsupported guarantees

1. **Runtime execution is not sandboxed.** The child still runs as the same OS user and can access files and network resources available to that user. Environment filtering is defense in depth, not isolation.
2. **Windows process-tree cleanup is incomplete.** The parent terminates the observed process; complete descendant termination requires a Windows Job Object backend. POSIX process-group cleanup is covered by a regression test.
3. **Third-party analyzer plugins execute in-process.** The allowlist is a trust decision, not a sandbox. A malicious or defective plugin can read/modify anything available to the X-Ray process or hang the scan.
4. **Interprocedural taint remains bounded and heuristic.** It resolves explicit absolute imports and top-level local functions, with a depth limit. Relative/dynamic imports, reflection, instance-method dispatch, broad aliasing, custom sanitizers and dynamic behavior can be missed. A reported flow is not proof of exploitability.
5. **The benchmark corpus is controlled and synthetic.** It models common application patterns but is not a test on arbitrary third-party production repositories. It measures expected-positive coverage, not full precision/recall.
6. **Production configuration is outside this repository CI.** Authentication, reverse proxies, host OS permissions, secrets managers, container profiles, deployment topology, and actual production data require environment-specific testing.
7. **No claim of zero vulnerabilities is made.** A clean test or scanner result only describes its tested inputs and rules.

## Recommended deployment boundary

Use static scanning for untrusted source. Run the optional runtime observer only for code you trust, ideally in a disposable, isolated OS account or externally enforced container/VM with read-only source mounts, restricted egress, bounded CPU/memory/process count, and no production credentials. Load third-party plugins only after independent review.
