"""Conservative Python taint tracing with bounded local interprocedural resolution."""
from __future__ import annotations

import ast
import time
from collections.abc import Callable
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
MAX_INTERPROCEDURAL_DEPTH = 8
MAX_CACHED_TARGET_FILES = 16


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


CallResolver = Callable[
    [
        str, str, ast.Call, list[set[str]], dict[str, set[str]],
        int, frozenset[tuple[str, str]],
    ],
    None,
]


class _ScopeFlow(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        nodes: list[Node],
        edges: list[Edge],
        flows: list[dict[str, Any]],
        findings: list[Finding],
        *,
        initial_taints: dict[str, set[str]] | None = None,
        source_locations: dict[str, tuple[str, int]] | None = None,
        seen_flow_pairs: set[tuple[str, str]] | None = None,
        seen_findings: set[tuple[str, str]] | None = None,
        call_resolver: CallResolver | None = None,
        depth: int = 0,
        call_stack: frozenset[tuple[str, str]] = frozenset(),
    ) -> None:
        self.path = path
        self.nodes = nodes
        self.edges = edges
        self.flows = flows
        self.findings = findings
        self.taints = {
            name: set(values) for name, values in (initial_taints or {}).items()
        }
        self.sources: dict[tuple[int, int, str], str] = {}
        self.source_locations = source_locations if source_locations is not None else {}
        self.seen_flow_pairs = seen_flow_pairs if seen_flow_pairs is not None else set()
        self.seen_findings = seen_findings if seen_findings is not None else set()
        self.call_resolver = call_resolver
        self.depth = depth
        self.call_stack = call_stack
        self.function = "<module>"

    def _child(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> _ScopeFlow:
        child = _ScopeFlow(
            self.path,
            self.nodes,
            self.edges,
            self.flows,
            self.findings,
            source_locations=self.source_locations,
            seen_flow_pairs=self.seen_flow_pairs,
            seen_findings=self.seen_findings,
            call_resolver=self.call_resolver,
            depth=self.depth + 1,
            call_stack=self.call_stack | {(self.path, node.name)},
        )
        child.function = node.name
        return child

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
        self.source_locations[identifier] = (self.path, int(line))
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
        child = self._child(node)
        for statement in node.body:
            child.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        child = self._child(node)
        for statement in node.body:
            child.visit(statement)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _name(node.func)
        positional_taints = [self._collect_taints(item) for item in node.args]
        keyword_taints = {
            item.arg: self._collect_taints(item.value)
            for item in node.keywords
            if item.arg is not None
        }
        tainted_sources: set[str] = set()
        for item in positional_taints:
            tainted_sources.update(item)
        for item in keyword_taints.values():
            tainted_sources.update(item)

        sink = SINKS.get(call_name)
        if sink is None and call_name.endswith(".execute"):
            sink = ("sql_query", "high")
        if sink is not None and tainted_sources:
            flow_type, severity = sink
            sink_id = f"data-sink:{self.path}:{node.lineno}:{node.col_offset}"
            if not any(item.id == sink_id for item in self.nodes):
                self.nodes.append(Node(
                    sink_id, "data_sink", flow_type, self.path, node.lineno,
                    {"expression": call_name, "function": self.function},
                ))
            for source_id in sorted(tainted_sources):
                pair = (source_id, sink_id)
                source_path, source_line = self.source_locations.get(
                    source_id, (self.path, 0)
                )
                if pair not in self.seen_flow_pairs:
                    self.seen_flow_pairs.add(pair)
                    self.edges.append(Edge(
                        source_id, sink_id, "data_flows_to",
                        Evidence(self.path, node.lineno, flow_type),
                    ))
                    cross_file = source_path != self.path
                    self.flows.append({
                        "source_node": source_id,
                        "sink_node": sink_id,
                        "sink_type": flow_type,
                        "sink_expression": call_name,
                        "source_path": source_path,
                        "sink_path": self.path,
                        "source_line": source_line,
                        "sink_line": node.lineno,
                        "function": self.function,
                        "cross_file": cross_file,
                        "confidence": (
                            "heuristic_interprocedural" if cross_file
                            else "heuristic_intra_function"
                        ),
                    })
            finding_key = (sink_id, flow_type)
            if finding_key not in self.seen_findings:
                self.seen_findings.add(finding_key)
                self.findings.append(Finding(
                    f"possible_tainted_data_to_{flow_type}",
                    severity,
                    "Potentially untrusted input reaches a sensitive operation; "
                    "review validation and parameterization.",
                    Evidence(self.path, node.lineno, flow_type),
                ))

        if self.call_resolver is not None and tainted_sources:
            self.call_resolver(
                self.path, self.function, node,
                positional_taints, keyword_taints,
                self.depth, self.call_stack,
            )
        self.generic_visit(node)


def _module_indexes(
    trees: dict[str, ast.Module],
) -> tuple[
    dict[str, set[str]],
    dict[str, dict[str, tuple[str, str]]],
    dict[str, dict[str, str]],
]:
    """Index top-level Python functions and explicit absolute imports."""
    module_to_path: dict[str, str] = {}
    functions: dict[str, set[str]] = {}
    imports: dict[str, dict[str, tuple[str, str]]] = {}
    module_aliases: dict[str, dict[str, str]] = {}

    for path, tree in trees.items():
        module = Path(path).with_suffix("").as_posix().replace("/", ".")
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        modules = {module}
        if module.startswith("src."):
            modules.add(module[4:])
        if module == "src":
            modules.add("")
        for name in modules:
            if name:
                module_to_path.setdefault(name, path)
        functions[path] = {
            item.name for item in tree.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        imports[path] = {}
        module_aliases[path] = {}

    def resolve_module(module: str) -> str | None:
        return module_to_path.get(module)

    for path, tree in trees.items():
        for item in tree.body:
            if isinstance(item, ast.ImportFrom) and item.level == 0 and item.module:
                target_path = resolve_module(item.module)
                for alias in item.names:
                    if alias.name == "*":
                        continue
                    local_name = alias.asname or alias.name
                    if target_path and alias.name in functions.get(target_path, set()):
                        imports[path][local_name] = (target_path, alias.name)
                    nested_module = f"{item.module}.{alias.name}"
                    if resolve_module(nested_module):
                        module_aliases[path][local_name] = nested_module
            elif isinstance(item, ast.Import):
                for alias in item.names:
                    target_path = resolve_module(alias.name)
                    local_name = alias.asname or alias.name
                    if target_path:
                        module_aliases[path][local_name] = alias.name
                    elif "." in alias.name:
                        prefix, _separator, _tail = alias.name.rpartition(".")
                        target_path = resolve_module(prefix)
                        if target_path:
                            module_aliases[path][alias.name] = prefix
    return functions, imports, module_aliases


def analyze_data_flows(
    root: Path,
    file_records: list[dict[str, Any]],
    max_bytes: int = 1_000_000,
    *,
    deadline: float | None = None,
    max_python_files: int = 2_000,
) -> tuple[list[dict[str, Any]], list[Node], list[Edge], list[Finding], dict[str, Any]]:
    """Trace recognized sources to sinks intra-function and through resolvable local calls."""
    flows: list[dict[str, Any]] = []
    nodes: list[Node] = []
    edges: list[Edge] = []
    findings: list[Finding] = []
    source_locations: dict[str, tuple[str, int]] = {}
    seen_flow_pairs: set[tuple[str, str]] = set()
    seen_findings: set[tuple[str, str]] = set()
    eligible = [
        str(record.get("path", ""))
        for record in file_records
        if Path(str(record.get("path", ""))).suffix.lower() == ".py"
        and record.get("status") == "analyzed"
    ]
    trees: dict[str, ast.Module] = {}
    indexed = 0
    skipped = 0
    stopped = False

    # First pass creates a compact project import/function index. The ASTs are
    # discarded after indexing so large projects do not retain every syntax tree.
    for path in eligible:
        if deadline is not None and time.monotonic() >= deadline:
            stopped = True
            break
        if indexed >= max_python_files:
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
        trees[path] = tree
        indexed += 1
    functions, imports, module_aliases = _module_indexes(trees)
    del trees

    module_paths: dict[str, str] = {}
    for path in functions:
        module = Path(path).with_suffix("").as_posix().replace("/", ".")
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        module_paths[module] = path
        if module.startswith("src."):
            module_paths[module[4:]] = path

    def _module_path_lookup(module: str) -> str | None:
        return module_paths.get(module)

    # Bind after the local helper exists; it is kept separate from report values.
    def call_resolver(
        caller_path: str,
        _caller_function: str,
        call_node: ast.Call,
        positional_taints: list[set[str]],
        keyword_taints: dict[str, set[str]],
        depth: int,
        call_stack: frozenset[tuple[str, str]],
    ) -> None:
        if depth >= MAX_INTERPROCEDURAL_DEPTH:
            return
        target: tuple[str, str] | None = None
        expression = _name(call_node.func)
        if isinstance(call_node.func, ast.Name):
            target = imports.get(caller_path, {}).get(call_node.func.id)
            if target is None and call_node.func.id in functions.get(caller_path, set()):
                target = (caller_path, call_node.func.id)
        else:
            for prefix, module in sorted(
                module_aliases.get(caller_path, {}).items(),
                key=lambda item: len(item[0]),
                reverse=True,
            ):
                if expression.startswith(prefix + "."):
                    function_name = expression[len(prefix) + 1 :]
                    target_path = _module_path_lookup(module)
                    if target_path and function_name in functions.get(target_path, set()):
                        target = (target_path, function_name)
                        break
        if target is None or target in call_stack:
            return
        target_path, function_name = target
        target_tree = target_tree_cache.get(target_path)
        if target_tree is None:
            target_source = read_project_text(root, target_path, max_bytes)
            if target_source is None:
                return
            try:
                parsed = ast.parse(target_source, filename=target_path)
            except (SyntaxError, RecursionError, ValueError):
                return
            target_tree = {
                item.name: item for item in parsed.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if len(target_tree_cache) >= MAX_CACHED_TARGET_FILES:
                target_tree_cache.pop(next(iter(target_tree_cache)))
            target_tree_cache[target_path] = target_tree
        function_node = target_tree.get(function_name)
        if function_node is None:
            return
        parameters = [
            *function_node.args.posonlyargs,
            *function_node.args.args,
            *function_node.args.kwonlyargs,
        ]
        initial: dict[str, set[str]] = {}
        for index, parameter in enumerate(parameters):
            values: set[str] = set()
            if index < len(positional_taints):
                values.update(positional_taints[index])
            values.update(keyword_taints.get(parameter.arg, set()))
            if values:
                initial[parameter.arg] = values
        if not initial:
            return
        child_stack = call_stack | {target}
        visitor = _ScopeFlow(
            target_path,
            nodes,
            edges,
            flows,
            findings,
            initial_taints=initial,
            source_locations=source_locations,
            seen_flow_pairs=seen_flow_pairs,
            seen_findings=seen_findings,
            call_resolver=call_resolver,
            depth=depth + 1,
            call_stack=child_stack,
        )
        visitor.function = function_name
        for statement in function_node.body:
            visitor.visit(statement)
            if deadline is not None and time.monotonic() >= deadline:
                return

    target_tree_cache: dict[
        str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    ] = {}

    analyzed = 0
    for path in eligible[:max_python_files]:
        if deadline is not None and time.monotonic() >= deadline:
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
        node_count = len(nodes)
        edge_count = len(edges)
        flow_count = len(flows)
        finding_count = len(findings)
        visitor = _ScopeFlow(
            path,
            nodes,
            edges,
            flows,
            findings,
            source_locations=source_locations,
            seen_flow_pairs=seen_flow_pairs,
            seen_findings=seen_findings,
            call_resolver=call_resolver,
        )
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
        "python_files_indexed": indexed,
        "python_files_skipped": skipped,
        "flow_count": len(flows),
        "interprocedural_flow_count": sum(bool(item.get("cross_file")) for item in flows),
        "max_python_files": max_python_files,
        "max_interprocedural_depth": MAX_INTERPROCEDURAL_DEPTH,
        "model": "bounded_local_interprocedural_ast_taint_heuristic",
        "limitations": [
            "Cross-file resolution is limited to statically indexed top-level Python functions "
            "and explicit absolute imports; relative/dynamic imports and instance-method "
            "dispatch are not resolved.",
            "Interprocedural call depth is capped; recursion and dynamic dispatch may be missed.",
            "Does not perform dynamic, reflection, or general alias analysis.",
            "Does not prove exploitability; review each flow and its sanitizers.",
            "Only listed source and sink patterns are recognized.",
        ],
    }
    return flows, nodes, edges, findings, summary

