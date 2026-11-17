# Analyzer and Connector Plugins

## Analyzer contract

An analyzer implements three members:

- `name`: stable unique plugin name.
- `extensions`: tuple of supported dotted file suffixes, such as `(".rs",)`.
- `analyze(context)`: returns an `AnalysisResult` containing typed `Node` and `Edge` objects.

The context provides the project root, file path, project-relative path, and file size. A plugin should be deterministic, bounded, read-only, and must not execute source files or make network calls.

Example:

```python
from xray.core.models import Node
from xray.plugins import AnalysisResult


class RustAnalyzer:
    name = "rust-basic"
    extensions = (".rs",)

    def analyze(self, context):
        # Parse source text; never compile or run the scanned project.
        return AnalysisResult(
            nodes=[
                Node(
                    id=f"rust-file:{context.relative_path}",
                    kind="source_unit",
                    name=context.path.name,
                    path=context.relative_path,
                )
            ]
        )
```

Register a plugin in application code:

```python
from xray.core.engine import XRayEngine
from xray.plugins import PluginRegistry
from xray.scanner import ProjectScanner

registry = PluginRegistry.with_builtins()
registry.register(RustAnalyzer())
engine = XRayEngine(scanner=ProjectScanner(registry=registry))
report = engine.scan("./source")
```

## Installed entry points

A third-party distribution can expose an analyzer through Python package metadata:

```toml
[project.entry-points."xray.analyzers"]
rust = "my_xray_rust_plugin:RustAnalyzer"
```

Entry points are deliberately not auto-loaded. The user must explicitly request discovery with `PluginRegistry.load_entry_points()` or the CLI's `--load-plugins` flag. Loading a plugin imports trusted third-party Python code into the X-Ray process. Review and pin plugin distributions before enabling them.

## Connector contract

A connector exposes:

- `root`: a stable `Path` representing the source root.
- `iter_files()`: deterministic iteration of `FileEntry` objects with absolute path, relative path, and byte size.

The built-in `LocalFilesystemConnector` does not follow symlinks, excludes common generated/vendor directories, and records traversal errors. Future archive, Git checkout, or remote connectors must preserve the same read-only and bounded behavior.

## Compatibility

Plugins should return relationships only between node IDs they add or IDs guaranteed by the scanner (for example, `file:<relative-path>`). The report graph validator records missing endpoints. Do not put source snippets, credentials, or raw secret values in node metadata, edge evidence, or findings.
