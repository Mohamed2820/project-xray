"""Non-executing Python structure extraction using the standard-library AST."""
from __future__ import annotations

import ast
from pathlib import Path

from xray.core.models import Edge, Evidence, Node


def analyze_python(path: Path, relative_path: str) -> tuple[list[Node], list[Edge]]:
    """Extract declarations, imports, and call sites without executing source code."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative_path)
    nodes: list[Node] = []
    edges: list[Edge] = []
    file_id = f"file:{relative_path}"
    nodes.append(Node(file_id, "file", relative_path, relative_path))

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.scope_ids = [file_id]

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            identifier = f"class:{relative_path}:{node.lineno}:{node.name}"
            nodes.append(
                Node(identifier, "class", node.name, relative_path, node.lineno)
            )
            edges.append(
                Edge(
                    self.scope_ids[-1],
                    identifier,
                    "contains",
                    Evidence(relative_path, node.lineno),
                )
            )
            self.scope_ids.append(identifier)
            self.generic_visit(node)
            self.scope_ids.pop()

        def _visit_function(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            qualified = ".".join(
                [self._scope_name(identifier) for identifier in self.scope_ids[1:]]
                + [node.name]
            )
            identifier = f"function:{relative_path}:{node.lineno}:{qualified}"
            nodes.append(
                Node(identifier, "function", qualified, relative_path, node.lineno)
            )
            edges.append(
                Edge(
                    self.scope_ids[-1],
                    identifier,
                    "contains",
                    Evidence(relative_path, node.lineno),
                )
            )
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
                nodes.append(
                    Node(target, "import", alias.name, relative_path, node.lineno)
                )
                edges.append(
                    Edge(
                        file_id,
                        target,
                        "imports",
                        Evidence(relative_path, node.lineno),
                    )
                )

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            module = "." * node.level + (node.module or "")
            target = f"import:{relative_path}:{node.lineno}:{module}"
            nodes.append(Node(target, "import", module, relative_path, node.lineno))
            edges.append(
                Edge(
                    file_id,
                    target,
                    "imports",
                    Evidence(relative_path, node.lineno),
                )
            )

        def visit_Call(self, node: ast.Call) -> None:
            name = ast.unparse(node.func)
            call_id = (
                f"call:{relative_path}:{node.lineno}:{node.col_offset}:{name}"
            )
            nodes.append(Node(call_id, "call", name, relative_path, node.lineno))
            edges.append(
                Edge(
                    self.scope_ids[-1],
                    call_id,
                    "calls",
                    Evidence(relative_path, node.lineno, name),
                )
            )
            self.generic_visit(node)

    Visitor().visit(tree)
    return nodes, edges
