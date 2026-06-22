import asyncio
import json
import logging
import shutil
import subprocess

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)

# Semgrep severity levels differ from our 4-tier system.
# https://semgrep.dev/docs/writing-rules/rule-syntax/#severity
SEMGREP_SEVERITY_MAP = {
    "error": "critical",
    "warning": "high",
    "inventory": "low",
    "info": "low",
}


def _map_severity(semgrep_severity: str) -> str:
    """Map semgrep severity to our 4-tier system (critical/high/medium/low)."""
    mapped = SEMGREP_SEVERITY_MAP.get(semgrep_severity.lower())
    if mapped:
        return mapped
    # Fallback: treat anything unrecognized as medium
    return "medium"


def _run_semgrep_sync(repo_path: str) -> list[Finding]:
    """Run semgrep synchronously in a thread."""
    semgrep_path = shutil.which("semgrep")
    if not semgrep_path:
        raise RuntimeError("semgrep is not installed or not on PATH")

    result = subprocess.run(
        [
            semgrep_path,
            "--config",
            "auto",
            "--json",
            "--no-force-color",
            "--exclude",
            ".venv",
            "--exclude",
            "node_modules",
            "--exclude",
            "vendor",
            "--exclude",
            "dist",
            "--exclude",
            "build",
            "--exclude",
            "docs",
            "--exclude",
            "examples",
            "--exclude",
            "scripts",
            "--exclude",
            "docs_src",
            repo_path,
        ],
        capture_output=True,
        timeout=300,
    )

    out = result.stdout.decode(errors="replace") if result.stdout else ""
    err = result.stderr.decode(errors="replace") if result.stderr else ""

    # semgrep exits non-zero when it finds issues.
    # Only treat as real error if stdout is empty.
    if result.returncode != 0 and not out:
        raise RuntimeError(
            err.strip() or out.strip() or f"semgrep exited with code {result.returncode}"
        )

    data = json.loads(out or "{}")
    findings: list[Finding] = []
    for sem_result in data.get("results", []):
        extra = sem_result.get("extra", {})
        raw_severity = extra.get("severity", "warning")
        findings.append(
            {
                "tool": "semgrep",
                "severity": _map_severity(raw_severity),
                "title": sem_result["check_id"],
                "description": extra.get("message", ""),
                "file_path": sem_result.get("path"),
                "rule_id": sem_result["check_id"],
            }
        )

    return findings


async def run_semgrep(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"semgrep_findings": []}

    try:
        findings = await asyncio.to_thread(_run_semgrep_sync, repo_path)
        logger.info("Semgrep found %d findings", len(findings))
        return {"semgrep_findings": findings}
    except Exception as exc:
        err_text = str(exc) or "Unknown error"
        logger.error("Semgrep scan failed: %s", err_text)
        return {"semgrep_findings": []}
