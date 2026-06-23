"""Tests for Checkov execution and output parsing."""

import json
import subprocess

import pytest

from app.graph.nodes import scan_iac_config


def _check(check_id: str) -> dict:
    return {
        "check_id": check_id,
        "check_name": f"Failed {check_id}",
        "severity": "HIGH",
        "file_path": "/Dockerfile",
        "guideline": "https://example.com",
        "resource": "Dockerfile.",
    }


def test_parse_checkov_multi_framework_output():
    output = json.dumps(
        [
            {"results": {"failed_checks": [_check("CKV_DOCKER_2")]}},
            {"results": {"failed_checks": [_check("CKV_K8S_8")]}},
        ]
    )

    parsed = scan_iac_config._parse_checkov_output(output)

    assert [item["check_id"] for item in parsed] == [
        "CKV_DOCKER_2",
        "CKV_K8S_8",
    ]


def test_parse_checkov_accepts_null_optional_fields():
    check = _check("CKV_DOCKER_2")
    check.update(
        {
            "severity": None,
            "check_name": None,
            "file_path": None,
            "repo_file_path": "/Dockerfile",
            "guideline": None,
            "resource": None,
        }
    )

    parsed = scan_iac_config._parse_checkov_output(
        json.dumps({"results": {"failed_checks": [check]}})
    )

    assert len(parsed) == 1
    assert parsed[0]["severity"] == "medium"
    assert parsed[0]["check_name"] == ""
    assert parsed[0]["file_path"] == "/Dockerfile"
    assert parsed[0]["guideline"] == ""
    assert parsed[0]["resource"] == ""


def test_docker_checkov_rules_get_docker_specific_finding_types():
    assert scan_iac_config._classify_checkov_check(
        "CKV_DOCKER_2",
        "Ensure that HEALTHCHECK instructions have been added to container images",
    ) == "iac_docker_healthcheck"
    assert scan_iac_config._classify_checkov_check(
        "CKV_DOCKER_3",
        "Ensure that a user for the container has been created",
    ) == "iac_docker_user"


@pytest.mark.anyio
async def test_dockerfile_is_not_excluded_from_checkov(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    monkeypatch.setattr(scan_iac_config.shutil, "which", lambda _: "checkov")
    captured_command = []

    def fake_run(command, **kwargs):
        captured_command.extend(command)
        output = json.dumps(
            {"results": {"failed_checks": [_check("CKV_DOCKER_2")]}}
        )
        return subprocess.CompletedProcess(command, 1, stdout=output, stderr="")

    monkeypatch.setattr(scan_iac_config.subprocess, "run", fake_run)

    result = await scan_iac_config.run_scan_iac_config(
        {"local_path": str(tmp_path), "error": None}
    )

    assert "--skip-framework" not in captured_command
    assert "--json" not in captured_command
    assert captured_command[captured_command.index("-o") + 1] == "json"
    assert len(result["iac_findings"]) == 1
    assert result["iac_findings"][0]["rule_id"] == "checkov_CKV_DOCKER_2"


@pytest.mark.anyio
async def test_checkov_unexpected_exit_code_returns_no_findings(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
    monkeypatch.setattr(scan_iac_config.shutil, "which", lambda _: "checkov")
    monkeypatch.setattr(
        scan_iac_config.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 2, stdout="", stderr="configuration error"
        ),
    )

    result = await scan_iac_config.run_scan_iac_config(
        {"local_path": str(tmp_path), "error": None}
    )

    assert result["iac_findings"] == []
