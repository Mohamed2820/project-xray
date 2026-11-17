# Analyzer and Connector Plugins

## Analyzer contract

An analyzer implements three members:

- name: stable unique plugin name.
- extensions: tuple of supported dotted file suffixes, such as (.rs,).
- analyze(context): returns an AnalysisResult containing typed Node and Edge objects.

The context provides the project root, file path, project-relative path, file size, and configured maximum file size. A plugin should be deterministic, bounded, read-only, and must not execute source files or make network calls.

## Installed entry points and trust boundary

Third-party entry points are never loaded automatically. To load one, the caller must
supply its exact entry-point name through an allowlist:

    registry = PluginRegistry.with_builtins()
    registry.load_entry_points(["reviewed-rust-analyzer"])

Loading a plugin imports and executes trusted third-party Python code inside the X-Ray
process. This is not a sandbox. A plugin can use the same filesystem, network, and
process permissions as X-Ray. Review the exact distribution and pin its version before
allowing it. Do not load plugins from untrusted projects or user-provided packages.

The CLI requires both --load-plugins and one or more exact --trusted-plugin NAME
arguments. A wildcard or implicit load-all mode is intentionally unsupported.

## Connector contract

A connector exposes:

- root: a stable Path representing the source root.
- iter_files(): an iterator of absolute paths, project-relative paths, and byte sizes.

The built-in filesystem connector does not follow symlinks, excludes common generated/vendor
directories, and caps visited entries and directory depth. The scanner additionally caps
file count, total input bytes, individual file size, and elapsed scan time.

Custom connectors must enforce equivalent bounds and must not follow symlinks or expose
paths outside their declared root.

## Compatibility

Plugins should return relationships only between node IDs they add or IDs guaranteed by
the scanner (for example, file:<relative-path>). The report graph validator records
missing endpoints. Do not put source snippets, credentials, or raw secret values in node
metadata, edge evidence, or findings.
