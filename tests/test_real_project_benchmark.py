import json
import socket
from pathlib import Path

from benchmarks.corpus import materialize_corpus
from benchmarks.run import run_benchmarks
from xray.scanner import scan_project


def test_phase_six_benchmark_matches_controlled_ground_truth() -> None:
    result = run_benchmarks()

    assert result["passed"] is True
    assert result["projects_total"] == 3
    assert result["projects_passed"] == 3
    assert result["matched_expected_findings"] == result["expected_findings_total"]
    assert result["expected_positive_coverage_percent"] == 100.0
    assert result["precision_measured"] is False

    commerce = next(item for item in result["projects"] if item["project"] == "commerce_api")
    assert commerce["interprocedural_flow_count"] >= 1

    runtime = result["runtime_probe"]
    assert runtime["status"] == "success"
    assert runtime["exit_code"] == 0
    assert runtime["fake_transport_observed"] is True
    assert runtime["network_events_observed"] == 0
    assert runtime["execution_is_sandboxed"] is False


def test_static_scan_never_executes_fixture_code_or_uses_network(
    tmp_path: Path, monkeypatch
) -> None:
    def forbidden_network(*_args, **_kwargs):
        raise AssertionError("Static scan unexpectedly attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_network)
    monkeypatch.setattr(socket.socket, "connect", forbidden_network)
    projects, osv_path = materialize_corpus(tmp_path / "corpus")

    report = scan_project(projects["commerce_api"], osv_database=osv_path)

    assert report.coverage["code_execution"] is False
    assert report.coverage["network_access"] is False
    assert report.coverage["scan_complete"] is True
    serialized = json.dumps(report.to_dict(), ensure_ascii=False)
    assert "xray_fixture_not_a_real_credential_123456789" not in serialized
    assert "fake-password" not in serialized


def test_generated_sources_and_parse_failures_are_distinguished(tmp_path: Path) -> None:
    projects, _osv_path = materialize_corpus(tmp_path / "corpus")
    report = scan_project(projects["commerce_api"])
    statuses = {item["path"]: item["status"] for item in report.files}

    assert statuses["src/generated/schema_client.py"] == "analyzed"
    assert statuses["src/api/syntax_fault.py"] == "analysis_error"
    assert any(node.kind == "function" and node.name == "create_order" for node in report.nodes)
