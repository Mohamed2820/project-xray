"""Non-executing Python structure extraction using the standard-library AST."""
from __future__ import annotations

import ast
import os
import stat
from pathlib import Path

from xray.analyzers.safe_io import read_project_text
from xray.core.models import Edge, Evidence, Node


def _read_source(path: Path, max_bytes: int) -> str:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ValueError("Source changed or exceeded the configured size limit.")
        content = handle.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError("Source exceeded the configured size limit while reading.")
    return content.decode("utf-8")


def _safe_symbol(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _safe_symbol(node.func)
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _safe_unparse(node)
    return type(node).__name__


def _argument_names(arguments: ast.arguments) -> list[str]:
    names = [item.arg for item in arguments.posonlyargs]
    names.extend(item.arg for item in arguments.args)
    if arguments.vararg:
        names.append("*" + arguments.vararg.arg)
    names.extend(item.arg for item in arguments.kwonlyargs)
    if arguments.kwarg:
        names.append("**" + arguments.kwarg.arg)
    return names


def analyze_python(
    path: Path,
    relative_path: str,
    *,
    max_bytes: int = 1_000_000,
    root: Path | None = None,
) -> tuple[list[Node], list[Edge]]:
    """Extract files, classes, functions, imports and call sites without execution."""
    if root is None:
        source = _read_source(path, max_bytes)
    else:
        source = read_project_text(root, relative_path, max_bytes)
        if source is None:
            raise ValueError("Source is unreadable, unsafe, or exceeds the configured size limit.")
    tree = ast.parse(source, filename=relative_path)
    nodes: list[Node] = [Node(
        f"file:{relative_path}", "file", relative_path, relative_path,
        metadata={"language": "python", "bytes": len(source.encode("utf-8"))},
    )]
    edges: list[Edge] = []
    file_id = f"file:{relative_path}"

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.scope_ids = [file_id]

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            identifier = f"class:{relative_path}:{node.lineno}:{node.name}"
            nodes.append(Node(
                identifier, "class", node.name, relative_path, node.lineno,
                {
                    "bases": [_safe_symbol(item) for item in node.bases],
                    "decorators": [_safe_symbol(item) for item in node.decorator_list],
                    "keyword_arguments": [item.arg for item in node.keywords],
                },
            ))
            edges.append(Edge(
                self.scope_ids[-1], identifier, "contains",
                Evidence(relative_path, node.lineno),
            ))
            self.scope_ids.append(identifier)
            self.generic_visit(node)
            self.scope_ids.pop()

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            qualified = ".".join(
                [self._scope_name(identifier) for identifier in self.scope_ids[1:]]
                + [node.name]
            )
            identifier = f"function:{relative_path}:{node.lineno}:{qualified}"
            nodes.append(Node(
                identifier, "function", qualified, relative_path, node.lineno,
                {
                    "parameters": _argument_names(node.args),
                    "positional_defaults": len(node.args.defaults),
                    "keyword_only_defaults": sum(
                        item is not None for item in node.args.kw_defaults
                    ),
                    "return_annotation": (
                        _safe_symbol(node.returns) if node.returns is not None else None
                    ),
                    "decorators": [_safe_symbol(item) for item in node.decorator_list],
                    "async": isinstance(node, ast.AsyncFunctionDef),
                    "is_generator": any(
                        isinstance(item, (ast.Yield, ast.YieldFrom))
                        for item in ast.walk(node)
                    ),
                },
            ))
            edges.append(Edge(
                self.scope_ids[-1], identifier, "contains",
                Evidence(relative_path, node.lineno),
            ))
            self.scope_ids.append(identifier)
            self.generic_visit(node)
            self.scope_ids.pop()

        @staticmethod
        def _scope_name(identifier: str) -> str:
            return identifier.rsplit(":", 1)[-1]

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def visit_Import(self, node: ast.Import) -> None:
            for index, alias in enumerate(node.names):
                target = f"import:{relative_path}:{node.lineno}:{index}:{alias.name}"
                nodes.append(Node(
                    target, "import", alias.name, relative_path, node.lineno,
                    {"alias": alias.asname},
                ))
                edges.append(Edge(
                    file_id, target, "imports", Evidence(relative_path, node.lineno)
                ))

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            module = "." * node.level + (node.module or "")
            target = f"import:{relative_path}:{node.lineno}:{module}"
            nodes.append(Node(
                target, "import", module, relative_path, node.lineno,
                {"names": [item.name for item in node.names]},
            ))
            edges.append(Edge(
                file_id, target, "imports", Evidence(relative_path, node.lineno)
            ))

        def visit_Call(self, node: ast.Call) -> None:
            name = _safe_symbol(node.func)
            call_id = f"call:{relative_path}:{node.lineno}:{node.col_offset}:{name}"
            nodes.append(Node(
                call_id, "call", name, relative_path, node.lineno,
                {
                    "positional_arguments": len(node.args),
                    "keyword_arguments": [item.arg for item in node.keywords],
                },
            ))
            edges.append(Edge(
                self.scope_ids[-1], call_id, "calls",
                Evidence(relative_path, node.lineno, name),
            ))
            self.generic_visit(node)

    Visitor().visit(tree)
    return nodes, edges


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (ValueError, TypeError):
        return type(node).__name__
