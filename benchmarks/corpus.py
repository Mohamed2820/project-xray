"""Declarative, isolated benchmark projects with explicit synthetic ground truth."""
from __future__ import annotations

import json
from pathlib import Path

PROJECT_FILES = {
    "commerce_api": {
        "pyproject.toml": '''[project]
name = "xray-benchmark-commerce-api"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["fixture-http-client==1.0.0"]
''',
        "poetry.lock": '''[[package]]
name = "fixture-http-client"
version = "1.0.0"
description = "Synthetic test-only direct dependency"
optional = false
python-versions = "*"

[package.dependencies]
fixture-url-parser = ">=0.1"

[[package]]
name = "fixture-url-parser"
version = "0.4.0"
description = "Synthetic transitive dependency"
optional = false
python-versions = "*"

[[package]]
name = "fixture-cert-store"
version = "2.0.0"
description = "Synthetic transitive dependency"
optional = false
python-versions = "*"
''',
        "requirements.txt": "git+https://fake-user:fake-password@git.example.invalid/fixture.git#egg=fixture-git-module\n",
        "src/api/__init__.py": '"""Synthetic commerce API benchmark package."""\n',
        "src/api/handlers.py": '''"""Intentionally vulnerable sample handlers."""
import os
import subprocess

import requests
from api.database import write_user


def handle_request(request, cursor):
    query = request.args.get("query")
    cursor.execute(query)

    expression = request.args.get("expression")
    preview = eval(expression)  # intentionally unsafe fixture

    command = request.args.get("command")
    subprocess.run(command, shell=True, check=False)

    target = os.getenv("PARTNER_URL")
    requests.get(target, timeout=2)

    return preview


def update_user(request, cursor):
    # Deliberate inter-file taint path. Current X-Ray does not propagate
    # taint through this imported function call into api.database.write_user.
    user_id = request.args.get("user_id")
    return write_user(cursor, user_id)
''',
        "src/api/database.py": '''"""Database layer for the cross-file benchmark gap."""


def write_user(cursor, user_id):
    statement = "UPDATE users SET active = 1 WHERE id = " + user_id
    return cursor.execute(statement)
''',
        "src/api/syntax_fault.py": '''"""Malformed Python sample for parse-error checks."""
def broken_handler(
    return "this file has a syntax error"
''',
        "src/config/credentials.py": '''"""Fake credential fixture for redaction tests."""
API_TOKEN = "xray_fixture_not_a_real_credential_123456789"
''',
        "src/generated/schema_client.py": '''# GENERATED FILE -- do not edit by hand.
"""Generated API client sample used to test generated-source inventory."""


def create_order(payload):
    return {"generated": True, "payload": payload}
''',
    },
    "mobile_admin": {
        "AndroidManifest.xml": '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
</manifest>
''',
        ".github/workflows/release.yml": '''name: intentionally-overprivileged-fixture

on:
  pull_request_target:

permissions: write-all

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Fixture deployment
        run: echo "This workflow is a static-analysis fixture only"
    secrets: inherit
''',
        "src/permissions.py": '''"""Android admin fixture module."""


def requested_features():
    return ["sms-sync", "file-manager"]
''',
    },
    "async_worker": {
        "package.json": '''{
  "name": "xray-benchmark-async-worker",
  "private": true,
  "version": "0.1.0",
  "dependencies": {
    "fixture-queue-client": "^1.0.0"
  }
}
''',
        "package-lock.json": '''{
  "name": "xray-benchmark-async-worker",
  "version": "0.1.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "xray-benchmark-async-worker",
      "version": "0.1.0",
      "dependencies": {
        "fixture-queue-client": "^1.0.0"
      }
    },
    "node_modules/fixture-queue-client": {
      "version": "1.0.0"
    },
    "node_modules/fixture-queue-client/node_modules/fixture-event-parser": {
      "version": "0.3.0"
    }
  }
}
''',
        "src/fake_transport.py": '''"""Deterministic local transport stub; no network I/O."""


def post_job(url, payload):
    if not url.endswith(".invalid/v1/jobs"):
        raise ValueError("Unexpected benchmark URL")
    return {"status": 202, "body": "simulated", "received": bool(payload)}
''',
        "src/runtime_probe.py": '''"""Safe, explicitly executed runtime benchmark entry point."""
from fake_transport import post_job


def calculate():
    # Harmless constant expression; tests runtime observation of dynamic eval.
    return eval("6 * 7")


def main():
    result = calculate()
    response = post_job(
        "https://vendor.example.invalid/v1/jobs",
        {"value": result},
    )
    if result != 42 or response["status"] != 202:
        raise AssertionError("Synthetic runtime fixture failed")
    return "ok"


if __name__ == "__main__":
    main()
''',
        "src/generated/queue_schema.py": '''# GENERATED FILE -- benchmark schema output.
"""Generated queue schema sample."""


def validate_message(message):
    return isinstance(message, dict) and "id" in message
''',
    },
}

OSV_DATA = {
    "vulns": [
        {
            "id": "XRAY-TEST-ONLY-0001",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "fixture-http-client"},
                    "versions": ["1.0.0"],
                }
            ],
        }
    ]
}


def materialize_corpus(root: Path) -> tuple[dict[str, Path], Path]:
    """Write controlled fixtures below root and return project paths and local OSV data."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    projects: dict[str, Path] = {}
    for project_name, files in PROJECT_FILES.items():
        project_root = root / project_name
        for relative_path, content in files.items():
            destination = project_root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        projects[project_name] = project_root
    osv_path = root / "osv-fixtures.json"
    osv_path.write_text(json.dumps(OSV_DATA), encoding="utf-8")
    return projects, osv_path
