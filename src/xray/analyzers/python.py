"""Non-executing Python structure extraction using AST."""
from __future__ import annotations

import ast
from pathlib import Path

from xray.core.models import Edge, Evidence, Node


def analyze_python(path: Path, relative_path: str) -> tuple[list[Node], list[Edge]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative_path)
    nodes: list[Node] = []
    edges: list[Edge] = []
    file_id = f"file:{relative_path}"
    nodes.append(Node(file_id, "file", relative_path, relative_path))

    class Visitor(ast.NodeVisitor):
        scope: list[str]

        def __init__(self) -> None:
            self.scope = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            identifier = f"class:{relative_path}:{node.lineno}:{node.name}"
            nodes.append(Node(identifier, "class", node.name, relative_path, node.lineno))
            edges.append(Edge(file_id, identifier, "contains", Evidence(relative_path, node.lineno)))
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            qualified = ".".join([*self.scope, node.name])
            identifier = f"function:{relative_path}:{node.lineno}:{qualified}"
            nodes.append(Node(identifier, "function", qualified, relative_path, node.lineno))
            edges.append(Edge(file_id, identifier, "contains", Evidence(relative_path, node.lineno)))
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()


        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                target = f"import:{alias.name}"
                nodes.append(Node(target, "import", alias.name, relative_path, node.lineno))
                edges.append(Edge(file_id, target, "imports", Evidence(relative_path, node.lineno)))
        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            module = "." * node.level + (node.module or "")
            target = f"import:{module}"
            nodes.append(Node(target, "import", module, relative_path, node.lineno))
            edges.append(Edge(file_id, target, "imports", Evidence(relative_path, node.lineno)))
        def visit_Call(self, node: ast.Call) -> None:
            name = ast.unparse(node.func) if hasattr(ast, "unparse") else type(node.func).__name__
            call_id = f"call:{relative_path}:{node.lineno}:{name}"
            nodes.append(Node(call_id, "call", name, relative_path, node.lineno))
            edges.append(Edge(file_id, call_id, "calls", Evidence(relative_path, node.lineno, name)))
            self.generic_visit(node)

    Visitor().visit(tree)
    return nodes, edges
