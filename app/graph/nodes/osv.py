import asyncio
import json
import shutil
import tempfile

from app.graph.state import AuditState, Finding


async def run_osv(state: AuditState) -> dict:
    temp_dir = tempfile.mkdtemp()
    try:
        await _clone_repo(state["repo_url"], temp_dir)
        process = await asyncio.create_subprocess_exec(
            "osv-scanner",
            "--format",
            "json",
            temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if not stdout:
            raise RuntimeError(stderr.decode(errors="replace") or "osv-scanner produced no JSON output")

        data = json.loads(stdout.decode())
        findings: list[Finding] = []
        for result in data.get("results", []):
            for package in result.get("packages", []):
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

        return {"osv_findings": findings}
    except Exception as exc:
        return {"osv_findings": [], "error": str(exc)}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def _clone_repo(repo_url: str, destination: str) -> None:
    process = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth",
        "1",
        repo_url,
        destination,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr.decode(errors="replace"))


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
