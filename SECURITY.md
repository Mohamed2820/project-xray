# Security Policy

## Supported versions

Security fixes are applied to the default branch. Users should run the latest
published source and keep the host Python runtime and operating system patched.

## Reporting a vulnerability

Do not publish credentials, private keys, exploit payloads containing real data,
or an unpatched vulnerability in a public issue. Use GitHub's private
vulnerability reporting feature for this repository when it is enabled. If that
feature is unavailable, contact the repository owner privately through a
verified channel.

Include the affected commit, impact, reproduction steps, and a proposed
mitigation. Redact all credentials and personal data.

## Security guarantees and limitations

Project X-Ray is a static inspection tool, not a sandbox or a penetration-test
certification. It does not execute the inspected project's code in its default
scan path and does not contact external services. Third-party plugins are
trusted in-process code and can exercise the same operating-system permissions
as the X-Ray process.

Secret detection is heuristic. A clean report does not prove that a project
contains no credentials or vulnerabilities. Runtime behavior, generated code,
encrypted values, unsupported languages, and external systems may not be visible
to static analysis.
