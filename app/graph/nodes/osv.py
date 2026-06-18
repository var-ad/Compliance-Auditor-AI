import asyncio
import json
import logging
import shutil
import subprocess

from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)


def _run_osv_sync(repo_path: str) -> list[Finding]:
    """Run osv-scanner synchronously in a thread."""
    osv_path = shutil.which("osv-scanner")
    if not osv_path:
        raise RuntimeError("osv-scanner is not installed or not on PATH")

    result = subprocess.run(
        [osv_path, "--format", "json", repo_path],
        capture_output=True,
        timeout=300,
    )

    stdout_str = (result.stdout.decode(errors="replace") if result.stdout else "").strip()
    stderr_str = (result.stderr.decode(errors="replace") if result.stderr else "").strip()

    # osv-scanner exits non-zero when it finds vulnerabilities.
    # If we got JSON on stdout, proceed — it found stuff.
    if not stdout_str:
        raise RuntimeError(
            stderr_str or f"osv-scanner exited with code {result.returncode} (no output)"
        )

    data = json.loads(stdout_str)
    findings: list[Finding] = []
    for scan_result in data.get("results", []):
        for package in scan_result.get("packages", []):
            for vuln in package.get("vulnerabilities", []):
                vuln_id = vuln["id"]
                findings.append(
                    {
                        "tool": "osv",
                        "severity": _severity(vuln),
                        "title": vuln_id,
                        "description": vuln.get("summary", vuln_id),
                        "file_path": None,
                        "rule_id": vuln_id,
                    }
                )

    if result.returncode != 0 and stderr_str:
        logger.info(
            "osv-scanner exited %d with stderr (expected): %s",
            result.returncode,
            stderr_str[:200],
        )

    return findings


async def run_osv(state: AuditState) -> dict:
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"osv_findings": [], "error": "No local_path in state"}

    try:
        findings = await asyncio.to_thread(_run_osv_sync, repo_path)
        logger.info("OSV found %d findings", len(findings))
        return {"osv_findings": findings}
    except Exception as exc:
        err_text = str(exc) or "Unknown error"
        logger.error("OSV scan failed: %s", err_text)
        return {"osv_findings": [], "error": err_text}


def _severity(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    if not severities:
        return "medium"

    score = severities[0].get("score")
    if score is None:
        return "medium"

    score_text = str(score).lower()
    for label in ("critical", "high", "medium", "low"):
        if label in score_text:
            return label

    try:
        numeric_score = float(score_text.split("/")[0])
    except ValueError:
        return "medium"

    if numeric_score >= 9:
        return "critical"
    if numeric_score >= 7:
        return "high"
    if numeric_score >= 4:
        return "medium"
    return "low"
