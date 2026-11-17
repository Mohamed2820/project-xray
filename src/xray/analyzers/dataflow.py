"""Conservative intra-function Python taint tracing from common inputs to sensitive sinks."""
from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import Any

from xray.analyzers.safe_io import read_project_text
from xray.core.models import Edge, Evidence, Finding, Node

SOURCE_CALLS = {
    "input": "interactive_input",
    "getenv": "environment_variable",
    "os.getenv": "environment_variable",
    "os.environ.get": "environment_variable",
    "request.args.get": "http_query_parameter",
    "request.form.get": "http_form_field",
    "request.headers.get": "http_header",
    "request.cookies.get": "http_cookie",
    "request.get_json": "http_request_body",
}
SOURCE_ATTRIBUTES = {
    "request.json": "http_request_body",
    "sys.argv": "command_line_argument",
}
SINKS = {
    "os.system": ("command_execution", "high"),
    "os.popen": ("command_execution", "high"),
    "subprocess.run": ("command_execution", "high"),
    "subprocess.Popen": ("command_execution", "high"),
    "subprocess.call": ("command_execution", "high"),
    "subprocess.check_call": ("command_execution", "high"),
    "subprocess.check_output": ("command_execution", "high"),
    "eval": ("dynamic_code_execution", "critical"),
    "exec": ("dynamic_code_execution", "critical"),
    "cursor.execute": ("sql_query", "high"),
    "connection.execute": ("sql_query", "high"),
    "db.execute": ("sql_query", "high"),
    "requests.get": ("outbound_http", "medium"),
    "requests.post": ("outbound_http", "medium"),
    "requests.put": ("outbound_http", "medium"),
    "requests.patch": ("outbound_http", "medium"),
    "urllib.request.urlopen": ("outbound_http", "medium"),
    "socket.sendall": ("socket_output", "medium"),
}


def _name(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (ValueError, TypeError, RecursionError):
        return type(node).__name__


def _source_type(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return SOURCE_CALLS.get(_name(node.func))
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return SOURCE_ATTRIBUTES.get(_name(node))
    return None


class _ScopeFlow(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        nodes: list[Node],
        edges: list[Edge],
        flows: list[dict[str, Any]],
        findings: list[Finding],
    ) -> None:
        self.path = path
        self.nodes = nodes
        self.edges = edges
        self.flows = flows
        self.findings = findings
        self.taints: dict[str, set[str]] = {}
        self.sources: dict[tuple[int, int, str], str] = {}
        self.source_lines: dict[str, int] = {}
        self.function = "<module>"

    def _register_source(self, node: ast.AST) -> str | None:
        source_type = _source_type(node)
        if source_type is None:
            return None
        line = getattr(node, "lineno", 0)
        column = getattr(node, "col_offset", 0)
        expression = _name(node.func) if isinstance(node, ast.Call) else _name(node)
        key = (line, column, expression)
        if key in self.sources:
            return self.sources[key]
        identifier = f"data-source:{self.path}:{line}:{column}"
        self.sources[key] = identifier
        self.source_lines[identifier] = line
        self.nodes.append(Node(
            identifier, "data_source", source_type, self.path, line,
            {"expression": expression, "function": self.function},
        ))
        return identifier

    def _collect_taints(self, node: ast.AST) -> set[str]:
        found: set[str] = set()
        if isinstance(node, ast.Name):
            found.update(self.taints.get(node.id, set()))
        source = self._register_source(node)
        if source:
            found.add(source)
        for child in ast.iter_child_nodes(node):
            found.update(self._collect_taints(child))
        return found

    @staticmethod
    def _target_names(node: ast.AST) -> set[str]:
        if isinstance(node, ast.Name):
            return {node.id}
        if isinstance(node, (ast.Tuple, ast.List)):
            result: set[str] = set()
            for item in node.elts:
                result.update(_ScopeFlow._target_names(item))
            return result
        return set()

    def visit_Assign(self, node: ast.Assign) -> None:
        taints = self._collect_taints(node.value)
        self.visit(node.value)
        for target in node.targets:
            for name in self._target_names(target):
                self.taints[name] = set(taints)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        taints = self._collect_taints(node.value) if node.value else set()
        if node.value:
            self.visit(node.value)
        for name in self._target_names(node.target):
            self.taints[name] = set(taints)
        self.visit(node.annotation)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        taints = self._collect_taints(node.value) | self._collect_taints(node.target)
        self.visit(node.value)
        for name in self._target_names(node.target):
            self.taints[name] = set(taints)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        child = _ScopeFlow(self.path, self.nodes, self.edges, self.flows, self.findings)
        child.function = node.name
        for statement in node.body:
            child.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        child = _ScopeFlow(self.path, self.nodes, self.edges, self.flows, self.findings)
        child.function = node.name
        for statement in node.body:
            child.visit(statement)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        self._register_source(node)
        call_name = _name(node.func)
        sink = SINKS.get(call_name)
        if sink is None and call_name.endswith(".execute"):
            sink = ("sql_query", "high")
        if sink is not None:
            tainted_sources: set[str] = set()
            for argument in node.args:
                tainted_sources.update(self._collect_taints(argument))
            for keyword in node.keywords:
                tainted_sources.update(self._collect_taints(keyword.value))
            if tainted_sources:
                flow_type, severity = sink
                sink_id = f"data-sink:{self.path}:{node.lineno}:{node.col_offset}"
                self.nodes.append(Node(
                    sink_id, "data_sink", flow_type, self.path, node.lineno,
                    {"expression": call_name, "function": self.function},
                ))
                for source_id in sorted(tainted_sources):
                    self.edges.append(Edge(
                        source_id, sink_id, "data_flows_to",
                        Evidence(self.path, node.lineno, flow_type),
                    ))
                    self.flows.append({
                        "source_node": source_id,
                        "sink_node": sink_id,
                        "sink_type": flow_type,
                        "sink_expression": call_name,
                        "source_path": self.path,
                        "source_line": self.source_lines.get(source_id),
                        "sink_line": node.lineno,
                        "function": self.function,
                        "confidence": "heuristic_intra_function",
                    })
                self.findings.append(Finding(
                    f"possible_tainted_data_to_{flow_type}",
                    severity,
                    "Potentially untrusted input reaches a sensitive operation; "
                    "review validation and parameterization.",
                    Evidence(self.path, node.lineno, flow_type),
                ))
        self.generic_visit(node)


def analyze_data_flows(
    root: Path,
    file_records: list[dict[str, Any]],
    max_bytes: int = 1_000_000,
    *,
    deadline: float | None = None,
    max_python_files: int = 2_000,
) -> tuple[list[dict[str, Any]], list[Node], list[Edge], list[Finding], dict[str, Any]]:
    """Trace recognized sources into sensitive sinks within the same function."""
    flows: list[dict[str, Any]] = []
    nodes: list[Node] = []
    edges: list[Edge] = []
    findings: list[Finding] = []
    analyzed = 0
    skipped = 0
    stopped = False
    for record in file_records:
        if deadline is not None and time.monotonic() >= deadline:
            stopped = True
            break
        path = str(record.get("path", ""))
        if Path(path).suffix.lower() != ".py" or record.get("status") != "analyzed":
            continue
        if analyzed >= max_python_files:
            stopped = True
            break
        source = read_project_text(root, path, max_bytes)
        if source is None:
            skipped += 1
            continue
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, RecursionError, ValueError):
            skipped += 1
            continue
        visitor = _ScopeFlow(path, nodes, edges, flows, findings)
        node_count = len(nodes)
        edge_count = len(edges)
        flow_count = len(flows)
        finding_count = len(findings)
        try:
            for statement in tree.body:
                visitor.visit(statement)
                if deadline is not None and time.monotonic() >= deadline:
                    stopped = True
                    break
        except RecursionError:
            del nodes[node_count:]
            del edges[edge_count:]
            del flows[flow_count:]
            del findings[finding_count:]
            skipped += 1
            continue
        analyzed += 1
        if stopped:
            break
    summary = {
        "status": "partial" if stopped else "analyzed",
        "python_files_analyzed": analyzed,
        "python_files_skipped": skipped,
        "flow_count": len(flows),
        "max_python_files": max_python_files,
        "model": "intra_function_ast_taint_heuristic",
        "limitations": [
            "Does not perform interprocedural, cross-file, dynamic, reflection, or alias analysis.",
            "Does not prove exploitability; review each flow and its sanitizers.",
            "Only listed source and sink patterns are recognized.",
        ],
    }
    return flows, nodes, edges, findings, summary
