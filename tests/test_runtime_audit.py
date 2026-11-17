import sys
from pathlib import Path

from xray.runtime.collector import RuntimeCollector


def test_audit_events_record_categories_not_sensitive_arguments(tmp_path: Path) -> None:
    secret = "secret-command-argument-value"
    collector = RuntimeCollector(tmp_path, max_events=50)
    with collector:
        sys.audit("subprocess.Popen", secret)
        sys.audit("socket.connect", ("example.invalid", 443))
        sys.audit("os.remove", "/tmp/private-file-name")

    event_types = {item["event_type"] for item in collector.events}
    assert "process_event" in event_types
    assert "network_event" in event_types
    assert "filesystem_event" in event_types
    assert secret not in repr(collector.events)
    assert "example.invalid" not in repr(collector.events)
    assert "/tmp/private-file-name" not in repr(collector.events)
