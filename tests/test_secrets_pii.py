"""Tests for the Gitleaks report-file integration."""

import json
import subprocess

from app.graph.nodes import scan_secrets_pii


def test_gitleaks_reads_json_report_when_stdout_is_empty(monkeypatch, tmp_path):
    leak = {
        "RuleID": "aws-access-token",
        "Description": "AWS access token",
        "File": "config.py",
        "StartLine": 12,
        "Commit": "1234567890abcdef",
        "Secret": "AKIAEXAMPLESECRET",
        "Author": "Developer",
    }

    monkeypatch.setattr(scan_secrets_pii, "_find_gitleaks", lambda: "gitleaks")

    def fake_run(command, **kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump([leak], report)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="")

    monkeypatch.setattr(scan_secrets_pii.subprocess, "run", fake_run)

    findings = scan_secrets_pii._run_gitleaks_scan(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "gitleaks_aws-access-token"
    assert findings[0]["finding_type"] == "cloud_credentials_exposed"
    assert "AKIAEXAMPLESECRET" not in findings[0]["description"]
    assert "[REDACTED]" in findings[0]["description"]


def test_gitleaks_returns_empty_when_report_is_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_secrets_pii, "_find_gitleaks", lambda: "gitleaks")

    def fake_run(command, **kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump([], report)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(scan_secrets_pii.subprocess, "run", fake_run)

    assert scan_secrets_pii._run_gitleaks_scan(str(tmp_path)) == []


def test_gitleaks_rejects_unexpected_exit_code(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_secrets_pii, "_find_gitleaks", lambda: "gitleaks")

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 2, stdout="", stderr="invalid configuration"
        )

    monkeypatch.setattr(scan_secrets_pii.subprocess, "run", fake_run)

    assert scan_secrets_pii._run_gitleaks_scan(str(tmp_path)) == []
