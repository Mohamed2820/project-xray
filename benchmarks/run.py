"""Run the controlled multi-project Project X-Ray benchmark."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from benchmarks.corpus import materialize_corpus
from xray.runtime.session import run_python_trace
from xray.scanner import scan_project

ROOT = Path(__file__).resolve().parent
GROUND_TRUTH = ROOT / "ground_truth.json"


def _dependency_counts(report: Any) -> dict[str, int]:
    summary = report.analyses["dependencies"]["summary"]
    return {
        "direct": int(summary["direct_count"]),
        "transitive": int(summary["transitive_count"]),
    }


def run_benchmarks() -> dict[str, Any]:
    truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    reports: dict[str, Any] = {}

    with tempfile.TemporaryDirectory(prefix="xray-phase6-corpus-") as temporary:
        projects, osv_path = materialize_corpus(Path(temporary))
        for case in truth["projects"]:
            name = case["id"]
            report = scan_project(
                projects[name],
                osv_database=osv_path if name == "commerce_api" else None,
            )
            reports[name] = report
            findings = {
                (finding.rule_id, finding.evidence.path)
                for finding in report.findings
            }
            expected = {
                (item["rule_id"], item["path"])
                for item in case["expected_findings"]
            }
            matched = expected & findings
            missing = sorted(expected - findings)
            inventory_status = {
                item["path"]: item["status"] for item in report.files
            }
            status_mismatches = {
                path: {"expected": status, "actual": inventory_status.get(path)}
                for path, status in case.get("expected_file_status", {}).items()
                if inventory_status.get(path) != status
            }
            missing_paths = sorted(
                set(case.get("expected_inventory_paths", [])) - set(inventory_status)
            )
            ast_call_pairs = {
                (node.path, node.name) for node in report.nodes if node.kind == "call"
            }
            expected_calls = {
                (item["path"], item["name"])
                for item in case.get("expected_ast_calls", [])
            }
            missing_calls = sorted(expected_calls - ast_call_pairs)
            import_pairs = {
                (node.path, node.name) for node in report.nodes if node.kind == "import"
            }
            expected_imports = {
                (item["path"], item["name"])
                for item in case.get("expected_imports", [])
            }
            missing_imports = sorted(expected_imports - import_pairs)
            dependency_counts = _dependency_counts(report)
            expected_counts = case["expected_dependency_counts"]
            count_match = dependency_counts == expected_counts
            passed = not (
                missing or status_mismatches or missing_paths or missing_calls
                or missing_imports or not count_match
                or not report.coverage.get("scan_complete", False)
                or report.coverage.get("graph_integrity_errors")
            )
            results.append({
                "project": name,
                "passed": passed,
                "expected_findings": len(expected),
                "matched_findings": len(matched),
                "missing_findings": [
                    {"rule_id": rule, "path": path} for rule, path in missing
                ],
                "dependency_counts": dependency_counts,
                "expected_dependency_counts": expected_counts,
                "dependency_counts_match": count_match,
                "missing_inventory_paths": missing_paths,
                "file_status_mismatches": status_mismatches,
                "missing_ast_calls": [
                    {"path": path, "name": call} for path, call in missing_calls
                ],
                "missing_imports": [
                    {"path": path, "name": module} for path, module in missing_imports
                ],
                "scan_complete": report.coverage.get("scan_complete", False),
                "graph_integrity_errors": report.coverage.get("graph_integrity_errors", []),
                "file_count": len(report.files),
                "finding_count": len(report.findings),
            })

        known_gaps: list[dict[str, Any]] = []
        for gap in truth.get("known_gaps", []):
            report = reports[gap["project"]]
            flows = report.analyses.get("data_flows", {}).get("items", [])
            detected = any(
                str(flow.get("sink_node", "")).startswith(
                    f"data-sink:{gap['sink_path']}:"
                )
                for flow in flows
            )
            known_gaps.append({
                **gap,
                "status": "detected" if detected else "not_detected",
            })

        worker = reports["async_worker"]
        with tempfile.TemporaryDirectory(prefix="xray-phase6-runtime-") as temporary:
            runtime = run_python_trace(
                worker,
                projects["async_worker"],
                "src/runtime_probe.py",
                Path(temporary) / "runtime-report.json",
                max_events=500,
                max_seconds=10,
            )

    events = runtime.get("events", [])
    event_paths = [
        item.get("path") for item in events if isinstance(item, dict) and item.get("path")
    ]
    runtime_result = {
        "status": runtime.get("status"),
        "exit_code": runtime.get("exit_code"),
        "function_calls_observed": sum(
            item.get("event_type") == "function_call" for item in events
        ),
        "fake_transport_observed": any(
            item.get("event_type") == "function_call"
            and item.get("path") == "src/fake_transport.py"
            for item in events
        ),
        "network_events_observed": sum(
            item.get("event_type") == "network_event" for item in events
        ),
        "execution_is_sandboxed": runtime.get("execution", {}).get("sandboxed"),
        "event_paths": sorted(set(event_paths)),
    }
    expected_total = sum(item["expected_findings"] for item in results)
    matched_total = sum(item["matched_findings"] for item in results)
    benchmark_passed = all(item["passed"] for item in results) and (
        runtime_result["status"] == "success"
        and runtime_result["exit_code"] == 0
        and runtime_result["fake_transport_observed"]
        and runtime_result["network_events_observed"] == 0
    )
    return {
        "benchmark_version": "1.0",
        "scope": "controlled_synthetic_projects",
        "passed": benchmark_passed,
        "projects_total": len(results),
        "projects_passed": sum(item["passed"] for item in results),
        "expected_findings_total": expected_total,
        "matched_expected_findings": matched_total,
        "expected_positive_coverage_percent": (
            round(100 * matched_total / expected_total, 2) if expected_total else 100.0
        ),
        "precision_measured": False,
        "projects": results,
        "known_gaps": known_gaps,
        "runtime_probe": runtime_result,
        "safety": {
            "static_scan_executes_source": False,
            "package_installation_performed": False,
            "package_registry_access_performed": False,
            "runtime_probe_uses_network_stub": True,
            "runtime_probe_is_sandboxed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON report destination.")
    args = parser.parse_args()
    result = run_benchmarks()
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
